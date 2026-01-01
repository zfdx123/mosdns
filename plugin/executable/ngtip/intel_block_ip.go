package ngtip

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/common"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginTypeIP = "intel_block_ip"

func init() {
	coremain.RegNewPluginFunc(PluginTypeIP, InitIP, func() any { return new(Args) })
}

var _ sequence.Executable = (*IntelBlockIP)(nil)

type IntelBlockIP struct {
	api         string
	key         string
	isCloud     bool
	client      *http.Client
	cache       *Cache
	whiteIP     *WhitelistIP
	whiteDomain *WhitelistDomain
	logger      *zap.Logger

	reloader *common.ReloadableFileSet
}

func InitIP(bp *coremain.BP, args any) (any, error) {
	arg := args.(*Args)

	if arg.Api == "" {
		return nil, fmt.Errorf("api required")
	}

	wi := NewWhitelistIP([]string{})
	wd := NewWhitelistDomain([]string{})

	ip := &IntelBlockIP{
		api:         arg.Api,
		key:         arg.Key,
		isCloud:     arg.IsCloud,
		client:      newHTTPClient(arg.Timeout),
		cache:       NewCache(time.Duration(arg.CacheTTL) * time.Second),
		whiteIP:     wi,
		whiteDomain: wd,
		logger:      bp.L(),
	}

	// 初始加载
	if arg.WhitelistFile != "" {
		if err := reloadWhitelist(arg.WhitelistFile, wd, wi); err != nil {
			return nil, err
		}

		r, err := common.NewReloadableFileSet(
			[]string{arg.WhitelistFile},
			time.Duration(arg.ReloadInterval)*time.Second,
			ip.logger,
			func() error {
				return reloadWhitelist(arg.WhitelistFile, wd, wi)
			},
		)
		if err != nil {
			return nil, err
		}
		ip.reloader = r
	}

	return ip, nil
}

func (b *IntelBlockIP) Exec(_ context.Context, qCtx *query_context.Context) error {
	resp := qCtx.R()
	if resp == nil {
		return nil
	}

	ipSet := map[string]struct{}{}
	domainSet := map[string]struct{}{}

	for _, rr := range resp.Answer {
		switch v := rr.(type) {

		case *dns.A:
			ip := v.A.String()
			if b.whiteIP.Match(ip) {
				continue
			}
			if v, ok := b.cache.Get(ip); ok {
				if v {
					qCtx.SetResponse(makeNXDOMAIN(qCtx.Q()))
					return nil
				}
				continue
			}
			ipSet[ip] = struct{}{}

		case *dns.AAAA:
			ip := v.AAAA.String()
			if b.whiteIP.Match(ip) {
				continue
			}
			if v, ok := b.cache.Get(ip); ok {
				if v {
					qCtx.SetResponse(makeNXDOMAIN(qCtx.Q()))
					return nil
				}
				continue
			}
			ipSet[ip] = struct{}{}

		case *dns.CNAME:
			d := strings.TrimSuffix(v.Target, ".")
			if b.whiteDomain.Match(d) {
				continue
			}
			if v, ok := b.cache.Get(d); ok {
				if v {
					qCtx.SetResponse(makeNXDOMAIN(qCtx.Q()))
					return nil
				}
				continue
			}
			domainSet[d] = struct{}{}
		}
	}

	if len(ipSet) == 0 {
		return nil
	}

	ips := make([]string, 0, len(ipSet))
	for d := range ipSet {
		ips = append(ips, d)
	}

	res, err := checkBatch(
		b.client,
		b.api,
		b.key,
		b.isCloud,
		ips,
	)
	if err != nil {
		return err
	}
	for ip, mal := range res {
		b.cache.Set(ip, mal)
		if mal {
			b.logger.Warn("[NGTIP] 恶意 IP", zap.String("IP", ip))
			qCtx.SetResponse(makeNXDOMAIN(qCtx.Q()))
			return nil
		}
	}

	if len(domainSet) == 0 {
		return nil
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}

	res, err = checkBatch(
		b.client,
		b.api,
		b.key,
		b.isCloud,
		domains,
	)
	if err != nil {
		b.logger.Error("[NGTIP]服务器错误:", zap.Error(err))
		return nil
	}
	for d, mal := range res {
		b.cache.Set(d, mal)
		if mal {
			b.logger.Warn("[NGTIP] 恶意 CNAME", zap.String("CNAME", d))
			qCtx.SetResponse(makeNXDOMAIN(qCtx.Q()))
			return nil
		}
	}

	return nil
}

func (b *IntelBlockIP) Close() {
	if b.reloader != nil {
		_ = b.reloader.Close()
	}
}

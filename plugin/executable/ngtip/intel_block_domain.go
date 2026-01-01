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
	"go.uber.org/zap"
)

const PluginTypeDomain = "intel_block_domain"

func init() {
	coremain.RegNewPluginFunc(PluginTypeDomain, InitDomain, func() any { return new(Args) })
}

var _ sequence.Executable = (*IntelBlockDomain)(nil)

type IntelBlockDomain struct {
	api     string
	key     string
	isCloud bool
	client  *http.Client
	cache   *Cache
	white   *WhitelistDomain
	logger  *zap.Logger

	reloader *common.ReloadableFileSet
}

func InitDomain(bp *coremain.BP, args any) (any, error) {
	arg := args.(*Args)

	if arg.Api == "" {
		return nil, fmt.Errorf("api required")
	}

	w := NewWhitelistDomain(nil)

	ib := &IntelBlockDomain{
		api:     arg.Api,
		key:     arg.Key,
		isCloud: arg.IsCloud,
		client:  newHTTPClient(arg.Timeout),
		cache:   NewCache(time.Duration(arg.CacheTTL) * time.Second),
		white:   w,
		logger:  bp.L(),
	}

	// 初始加载
	if arg.WhitelistFile != "" {
		if err := reloadWhitelist(arg.WhitelistFile, w, nil); err != nil {
			return nil, err
		}

		r, err := common.NewReloadableFileSet(
			[]string{arg.WhitelistFile},
			time.Duration(arg.ReloadInterval)*time.Second,
			ib.logger,
			func() error {
				return reloadWhitelist(arg.WhitelistFile, w, nil)
			},
		)
		if err != nil {
			return nil, err
		}
		ib.reloader = r
	}

	return ib, nil
}

func (b *IntelBlockDomain) Exec(_ context.Context, qCtx *query_context.Context) error {
	req := qCtx.Q()

	toQuery := make(map[string]struct{})

	for _, q := range req.Question {
		d := strings.TrimSuffix(q.Name, ".")

		// 白名单（O1）
		if b.white != nil && b.white.Match(d) {
			continue
		}

		// Cache（O1）
		if v, ok := b.cache.Get(d); ok {
			if v {
				qCtx.SetResponse(makeNXDOMAIN(req))
				return nil
			}
			continue
		}

		// 去重收集
		toQuery[d] = struct{}{}
	}

	if len(toQuery) == 0 {
		return nil
	}

	// map → slice（一次）
	domains := make([]string, 0, len(toQuery))
	for d := range toQuery {
		domains = append(domains, d)
	}

	res, err := checkBatch(
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

	for domain, mal := range res {
		b.cache.Set(domain, mal)
		if mal {
			b.logger.Warn("[NGTIP] 恶意域名:", zap.String("domain", domain))
			qCtx.SetResponse(makeNXDOMAIN(req))
			return nil
		}
	}

	return nil
}

func (b *IntelBlockDomain) Close() {
	if b.reloader != nil {
		_ = b.reloader.Close()
	}
}

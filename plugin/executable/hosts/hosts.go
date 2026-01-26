/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package hosts

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	pkgHosts "github.com/IrineSistiana/mosdns/v5/pkg/hosts"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/common"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Entries      []string `yaml:"entries"`
	Files        []string `yaml:"files"`
	AutoReload   bool     `yaml:"auto_reload"`
	DebounceTime uint     `yaml:"debounce_time"`
}

type Hosts struct {
	current atomic.Value // *pkgHosts.Hosts
	args    *Args
	bp      *coremain.BP

	logger *zap.Logger

	reloader *common.ReloadableFileSet
}

var _ sequence.Executable = (*Hosts)(nil)

func Init(bp *coremain.BP, args any) (any, error) {
	h := &Hosts{
		bp:     bp,
		args:   args.(*Args),
		logger: bp.L(),
	}

	// 初始加载
	hostsInst, err := loadHosts(h.args)
	if err != nil {
		return nil, err
	}
	h.current.Store(hostsInst)

	if h.args.AutoReload && len(h.args.Files) > 0 {
		r, err := common.NewReloadableFileSet(
			h.args.Files,
			time.Duration(h.args.DebounceTime)*time.Second,
			h.logger,
			h.reload,
		)
		if err != nil {
			return nil, err
		}
		h.reloader = r
	}

	return h, nil
}

func loadHosts(args *Args) (*pkgHosts.Hosts, error) {
	m := domain.NewMixMatcher[*pkgHosts.IPs]()
	m.SetDefaultMatcher(domain.MatcherFull)

	for i, e := range args.Entries {
		if err := domain.Load(m, e, pkgHosts.ParseIPs); err != nil {
			return nil, fmt.Errorf("hosts entry #%d error: %w", i, err)
		}
	}

	for i, f := range args.Files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read hosts file #%d %s error: %w", i, f, err)
		}
		if err := domain.LoadFromTextReader(m, bytes.NewReader(b), pkgHosts.ParseIPs); err != nil {
			return nil, fmt.Errorf("parse hosts file #%d %s error: %w", i, f, err)
		}
	}

	return pkgHosts.NewHosts(m), nil
}

func (h *Hosts) reload() error {
	nh, err := loadHosts(h.args)
	if err != nil {
		return err
	}

	h.current.Store(nh)
	h.logger.Info("hosts reloaded", zap.Int("records", nh.Len()))
	return nil
}

func (d *Hosts) Close() error {
	if d.reloader != nil {
		return d.reloader.Close()
	}
	return nil
}

func (h *Hosts) get() *pkgHosts.Hosts {
	return h.current.Load().(*pkgHosts.Hosts)
}

func (h *Hosts) Exec(_ context.Context, qCtx *query_context.Context) error {
	if r := h.get().LookupMsg(qCtx.Q()); r != nil {
		qCtx.SetResponse(r)
	}
	return nil
}

func (h *Hosts) Response(q *dns.Msg) *dns.Msg {
	return h.get().LookupMsg(q)
}

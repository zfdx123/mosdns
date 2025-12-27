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

package base_ip

import (
	"context"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

var _ sequence.Matcher = (*Matcher)(nil)

type Args struct {
	IPs    []string `yaml:"ips"`
	IPSets []string `yaml:"ip_sets"`
	Files  []string `yaml:"files"`
}

type MatchFunc func(qCtx *query_context.Context, m netlist.Matcher) (bool, error)

type Matcher struct {
	match MatchFunc

	// 注意：这里存的是“活的 matcher”
	// 可能是 DynamicMatcherGroup，也可能是 netlist.List
	matchers []netlist.Matcher
}

func (m *Matcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	// 每次 Match 都使用当前 matcher 状态
	return m.match(qCtx, ip_set.MatcherGroup(m.matchers))
}

func NewMatcher(bq sequence.BQ, args *Args, f MatchFunc) (m *Matcher, err error) {
	m = &Matcher{
		match: f,
	}

	// 引用其他 ip_set（热的）
	for _, tag := range args.IPSets {
		p := bq.M().GetPlugin(tag)
		provider, _ := p.(data_provider.IPMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("cannot find ipset %s", tag)
		}

		// 这里拿到的是 DynamicMatcherGroup
		m.matchers = append(m.matchers, provider.GetIPMatcher())
	}

	// 匿名 IP / file（静态）
	if len(args.IPs)+len(args.Files) > 0 {
		l := netlist.NewList()
		if err := ip_set.LoadFromIPsAndFiles(args.IPs, args.Files, l); err != nil {
			return nil, err
		}
		l.Sort()
		if l.Len() > 0 {
			m.matchers = append(m.matchers, l)
		}
	}

	return m, nil
}

// ParseQuickSetupArgs parses expressions and "ip_set"s to args.
// Format: "([ip] | [$ip_set_tag] | [&ip_list_file])..."
func ParseQuickSetupArgs(s string) *Args {
	cutPrefix := func(s string, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p), true
		}
		return s, false
	}

	args := new(Args)
	for _, exp := range strings.Fields(s) {
		if tag, ok := cutPrefix(exp, "$"); ok {
			args.IPSets = append(args.IPSets, tag)
		} else if path, ok := cutPrefix(exp, "&"); ok {
			args.Files = append(args.Files, path)
		} else {
			args.IPs = append(args.IPs, exp)
		}
	}
	return args
}

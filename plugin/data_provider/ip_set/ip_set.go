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

package ip_set

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/common"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"go.uber.org/zap"
)

const PluginType = "ip_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewIPSet(bp, args.(*Args))
}

type Args struct {
	IPs          []string `yaml:"ips"`
	Sets         []string `yaml:"sets"`
	Files        []string `yaml:"files"`
	AutoReload   bool     `yaml:"auto_reload"`
	DebounceTime uint     `yaml:"debounce_time"`
}

var _ data_provider.IPMatcherProvider = (*IPSet)(nil)

type IPSet struct {
	bp *coremain.BP

	logger *zap.Logger

	args     *Args
	dynamic  *DynamicMatcherGroup
	reloader *common.ReloadableFileSet

	files []string
}

func (d *IPSet) GetIPMatcher() netlist.Matcher {
	return d.dynamic
}

func NewIPSet(bp *coremain.BP, args *Args) (*IPSet, error) {
	d := &IPSet{
		bp:      bp,
		args:    args,
		dynamic: NewDynamicMatcherGroup(),
		logger:  bp.L(),
	}

	if err := d.rebuildMatcher(); err != nil {
		return nil, err
	}

	if args.AutoReload && len(args.Files) > 0 {
		r, err := common.NewReloadableFileSet(
			args.Files,
			time.Duration(d.args.DebounceTime)*time.Second,
			d.logger,
			d.rebuildMatcher,
		)
		if err != nil {
			return nil, err
		}
		d.reloader = r
	}

	return d, nil
}

func (d *IPSet) rebuildMatcher() error {
	var matchers []netlist.Matcher

	// IPs + Files
	l := netlist.NewList()
	if err := LoadFromIPsAndFiles(d.args.IPs, d.args.Files, l); err != nil {
		return err
	}
	l.Sort()
	if l.Len() > 0 {
		matchers = append(matchers, l)

	}

	if l.Len() > 0 {
		matchers = append(matchers, l)
		d.logger.Info(
			"[IP] loaded",
			zap.Int("ip", l.Len()),
			zap.Int("files", len(d.args.Files)),
		)
	}

	// 引用其他 ip_set
	for _, tag := range d.args.Sets {
		p, _ := d.bp.M().GetPlugin(tag).(data_provider.IPMatcherProvider)
		if p == nil {
			return fmt.Errorf("%s is not IPMatcherProvider", tag)
		}
		matchers = append(matchers, p.GetIPMatcher())
	}

	d.dynamic.Update(MatcherGroup(matchers))

	d.logger.Info(
		"[IP] rebuild finished",
		zap.Int("matchers", len(matchers)),
	)
	return nil
}

func (d *IPSet) Close() error {
	if d.reloader != nil {
		return d.reloader.Close()
	}
	return nil
}

func parseNetipPrefix(s string) (netip.Prefix, error) {
	if strings.ContainsRune(s, '/') {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

func LoadFromIPsAndFiles(ips []string, fs []string, l *netlist.List) error {
	if err := LoadFromIPs(ips, l); err != nil {
		return err
	}
	if err := LoadFromFiles(fs, l); err != nil {
		return err
	}
	return nil
}

func LoadFromIPs(ips []string, l *netlist.List) error {
	for i, s := range ips {
		p, err := parseNetipPrefix(s)
		if err != nil {
			return fmt.Errorf("invalid ip #%d %s, %w", i, s, err)
		}
		l.Append(p)
	}
	return nil
}

func LoadFromFiles(fs []string, l *netlist.List) error {
	for i, f := range fs {
		if err := LoadFromFile(f, l); err != nil {
			return fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
	}
	return nil
}

func LoadFromFile(f string, l *netlist.List) error {
	if len(f) == 0 {
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	return netlist.LoadFromReader(l, bytes.NewReader(b))
}

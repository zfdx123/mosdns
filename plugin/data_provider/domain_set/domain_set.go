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

package domain_set

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/common"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"go.uber.org/zap"
)

const PluginType = "domain_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewDomainSet(bp, args.(*Args))
}

type Args struct {
	Exps       []string `yaml:"exps"`
	Sets       []string `yaml:"sets"`
	Files      []string `yaml:"files"`
	AutoReload bool     `yaml:"auto_reload"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	dynamicGroup *DynamicMatcherGroup
	reloader     *common.ReloadableFileSet

	files []string

	bp   *coremain.BP
	args *Args

	logger *zap.Logger
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return d.dynamicGroup
}

// ---------------- matcher rebuild ----------------

func (d *DomainSet) rebuildMatcher() error {
	d.logger.Info("[DOMAIN] rebuilding domain matcher")

	var matchers []domain.Matcher[struct{}]

	// expressions + files
	if len(d.args.Exps) > 0 || len(d.args.Files) > 0 {
		m := domain.NewDomainMixMatcher()
		if err := LoadExpsAndFiles(d.args.Exps, d.args.Files, m); err != nil {
			return err
		}
		if m.Len() > 0 {
			matchers = append(matchers, m)
			d.logger.Info(
				"[DOMAIN] loaded",
				zap.Int("domains", m.Len()),
				zap.Int("files", len(d.args.Files)),
				zap.Int("exps", len(d.args.Exps)),
			)
		}
	}

	// referenced sets
	for _, tag := range d.args.Sets {
		p, ok := d.bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if !ok {
			return fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matchers = append(matchers, p.GetDomainMatcher())
	}

	d.dynamicGroup.Update(MatcherGroup(matchers))

	d.logger.Info(
		"[DOMAIN] rebuild finished",
		zap.Int("matchers", len(matchers)),
	)

	return nil
}

// ---------------- constructor ----------------

func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{
		bp:           bp,
		args:         args,
		dynamicGroup: NewDynamicMatcherGroup(),
		logger:       bp.L(),
	}

	if err := ds.rebuildMatcher(); err != nil {
		return nil, err
	}

	if args.AutoReload && len(args.Files) > 0 {
		r, err := common.NewReloadableFileSet(
			args.Files,
			500*time.Millisecond,
			ds.logger,
			ds.rebuildMatcher,
		)
		if err != nil {
			return nil, err
		}
		ds.reloader = r
	}

	return ds, nil
}

func (d *DomainSet) Close() error {
	if d.reloader != nil {
		return d.reloader.Close()
	}
	return nil
}

// ---------------- loading helpers ----------------

func LoadExpsAndFiles(exps []string, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	return LoadFiles(fs, m)
}

func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := m.Add(exp, struct{}{}); err != nil {
			return fmt.Errorf("expression #%d (%s): %w", i, exp, err)
		}
	}
	return nil
}

func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
			return fmt.Errorf("file #%d (%s): %w", i, f, err)
		}
	}
	return nil
}

func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	return domain.LoadFromTextReader(m, bytes.NewReader(b), nil)
}

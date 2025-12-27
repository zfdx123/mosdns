package domain_set

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/fsnotify/fsnotify"
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

	watcher *fsnotify.Watcher
	files   []string

	bp   *coremain.BP
	args *Args
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return d.dynamicGroup
}

// ---------------- matcher rebuild ----------------

func (d *DomainSet) rebuildMatcher() error {
	mlog.L().Info("[domain_set] rebuilding domain matcher")

	var matchers []domain.Matcher[struct{}]

	// expressions + files
	if len(d.args.Exps) > 0 || len(d.args.Files) > 0 {
		m := domain.NewDomainMixMatcher()
		if err := LoadExpsAndFiles(d.args.Exps, d.args.Files, m); err != nil {
			return err
		}
		if m.Len() > 0 {
			matchers = append(matchers, m)
			mlog.L().Info(
				"[domain_set] domains loaded",
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

	mlog.L().Info(
		"[domain_set] rebuild finished",
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
	}

	if err := ds.rebuildMatcher(); err != nil {
		return nil, err
	}

	if args.AutoReload && len(args.Files) > 0 {
		if err := ds.startFileWatcher(); err != nil {
			return nil, err
		}
	}

	return ds, nil
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

// ---------------- file watcher ----------------

func (d *DomainSet) startFileWatcher() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	d.watcher = w

	for _, f := range d.args.Files {
		abs, err := filepath.Abs(f)
		if err != nil {
			return err
		}
		abs = filepath.Clean(abs)

		if err := w.Add(abs); err != nil {
			return err
		}
		d.files = append(d.files, abs)
	}

	mlog.L().Info(
		"[domain_set] file watcher enabled",
		zap.Strings("files", d.files),
	)

	go d.watchFiles()
	return nil
}

func (d *DomainSet) watchFiles() {
	var lastReload time.Time

	for {
		select {
		case e, ok := <-d.watcher.Events:
			if !ok {
				return
			}

			path := filepath.Clean(e.Name)
			if !d.isMonitored(path) {
				continue
			}

			if e.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			if time.Since(lastReload) < 300*time.Millisecond {
				continue
			}
			lastReload = time.Now()

			mlog.L().Info(
				"[domain_set] file changed, reloading",
				zap.String("file", path),
			)

			if err := d.rebuildMatcher(); err != nil {
				mlog.L().Error("[domain_set] reload failed", zap.Error(err))
			} else {
				mlog.L().Info("[domain_set] reload success")
			}
		}
	}
}

func (d *DomainSet) isMonitored(p string) bool {
	for _, f := range d.files {
		if f == p {
			return true
		}
	}
	return false
}

func (d *DomainSet) Close() error {
	if d.watcher != nil {
		return d.watcher.Close()
	}
	return nil
}

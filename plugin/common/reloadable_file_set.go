package common

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type ReloadFunc func() error

type ReloadableFileSet struct {
	files      []string
	watcher    *fsnotify.Watcher
	reload     ReloadFunc
	debounce   time.Duration
	lastReload time.Time
	mu         sync.Mutex
	logger     *zap.Logger
}

func NewReloadableFileSet(
	files []string,
	debounce time.Duration,
	logger *zap.Logger,
	reload ReloadFunc,
) (*ReloadableFileSet, error) {

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	r := &ReloadableFileSet{
		watcher:  w,
		reload:   reload,
		debounce: debounce,
		logger:   logger,
	}

	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			return nil, err
		}
		abs = filepath.Clean(abs)
		if err := w.Add(abs); err != nil {
			w.Close()
			return nil, err
		}
		r.files = append(r.files, abs)
	}

	go r.watch()
	return r, nil
}

func (r *ReloadableFileSet) watch() {
	timers := make(map[string]*time.Timer)
	mu := sync.Mutex{}

	for {
		select {
		case ev, ok := <-r.watcher.Events:
			if !ok {
				return
			}

			// 非原子写入：只关心 Write / Create
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			path := filepath.Clean(ev.Name)
			if !r.isMonitored(path) {
				continue
			}

			mu.Lock()
			if t, ok := timers[path]; ok {
				// 写还在继续，重置计时器
				t.Stop()
			}

			timers[path] = time.AfterFunc(r.debounce, func() {
				// debounce 时间内没有新写入 → 认为稳定
				if err := r.reload(); err != nil {
					r.logger.Error("reload failed", zap.Error(err))
				} else {
					r.logger.Info("reload success")
				}
			})
			mu.Unlock()

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				r.logger.Warn("watcher error", zap.Error(err))
			}
		}
	}
}

func (r *ReloadableFileSet) isMonitored(p string) bool {
	for _, f := range r.files {
		if f == p {
			return true
		}
	}
	return false
}

func (r *ReloadableFileSet) Close() error {
	if r.watcher != nil {
		return r.watcher.Close()
	}
	return nil
}

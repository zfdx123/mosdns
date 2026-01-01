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
			return nil, err
		}
		r.files = append(r.files, abs)
	}

	go r.watch()
	return r, nil
}

func (r *ReloadableFileSet) watch() {
	for {
		select {
		case ev, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}

			path := filepath.Clean(ev.Name)
			if !r.isMonitored(path) {
				continue
			}

			r.mu.Lock()
			if time.Since(r.lastReload) < r.debounce {
				r.mu.Unlock()
				continue
			}
			r.lastReload = time.Now()
			r.mu.Unlock()

			go func() {
				if err := r.reload(); err != nil {
					r.logger.Error("reload failed", zap.Error(err))
				} else {
					r.logger.Info("reload success")
				}
			}()

		case err := <-r.watcher.Errors:
			r.logger.Warn("watcher error", zap.Error(err))
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

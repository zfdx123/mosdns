package runtime_stats

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/go-chi/chi/v5"
)

const PluginType = "runtime_stats"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	MaxDomains int `yaml:"max_domains"`
}

type runtimeStats struct {
	mu sync.Mutex

	startTime time.Time

	totalQueries int64
	domainStats  map[string]int64
	qtypeStats   map[uint16]int64

	maxDomains int
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	rs := &runtimeStats{
		startTime:   time.Now(),
		domainStats: make(map[string]int64),
		qtypeStats:  make(map[uint16]int64),
		maxDomains:  cfg.MaxDomains,
	}
	bp.RegAPI(rs.Api())
	return rs, nil
}

func (r *runtimeStats) Exec(_ context.Context, qCtx *query_context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.totalQueries++

	for _, q := range qCtx.Q().Question {
		domain := strings.TrimSuffix(q.Name, ".")
		r.domainStats[domain]++
		r.qtypeStats[q.Qtype]++
	}

	// 防止域名无限增长（简单保护）
	if r.maxDomains > 0 && len(r.domainStats) > r.maxDomains {
		r.domainStats = make(map[string]int64)
	}

	return nil
}

func (r *runtimeStats) Api() *chi.Mux {
	rtr := chi.NewRouter()

	// GET /plugins/<tag>/stats
	rtr.Get("/stats", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()

		resp := map[string]any{
			"uptime_seconds": int64(time.Since(r.startTime).Seconds()),
			"total_queries":  r.totalQueries,
			"domains":        len(r.domainStats),
			"qtypes":         r.qtypeStats,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// GET /plugins/<tag>/show
	rtr.Get("/show", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()

		type Item struct {
			Domain string `json:"domain"`
			Count  int64  `json:"count"`
		}

		stats := make([]Item, 0, len(r.domainStats))
		for d, c := range r.domainStats {
			stats = append(stats, Item{Domain: d, Count: c})
		}
		r.mu.Unlock()

		sort.Slice(stats, func(i, j int) bool {
			return stats[i].Count > stats[j].Count
		})

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// GET /plugins/<tag>/reset
	rtr.Get("/reset", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		r.domainStats = make(map[string]int64)
		r.qtypeStats = make(map[uint16]int64)
		r.totalQueries = 0
		r.startTime = time.Now()
		r.mu.Unlock()

		resp := map[string]any{
			"msg": "success",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return rtr
}

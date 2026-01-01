package ngtip

import (
	"strings"
	"sync/atomic"
)

type WhitelistDomain struct {
	v atomic.Value // map[string]struct{}
}

func NewWhitelistDomain(domains []string) *WhitelistDomain {
	w := &WhitelistDomain{}
	w.Store(domains)
	return w
}

func (w *WhitelistDomain) Store(domains []string) {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d != "" {
			m[d] = struct{}{}
		}
	}
	w.v.Store(m)
}

func (w *WhitelistDomain) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	m := w.v.Load().(map[string]struct{})
	_, ok := m[domain]
	return ok
}

type WhitelistIP struct {
	v atomic.Value // map[string]struct{}
}

func NewWhitelistIP(ips []string) *WhitelistIP {
	w := &WhitelistIP{}
	w.Store(ips)
	return w
}

func (w *WhitelistIP) Store(ips []string) {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		m[ip] = struct{}{}
	}
	w.v.Store(m)
}

func (w *WhitelistIP) Match(ip string) bool {
	m := w.v.Load().(map[string]struct{})
	_, ok := m[ip]
	return ok
}

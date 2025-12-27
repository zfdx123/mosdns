package ip_set

import (
	"net/netip"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
)

type MatcherGroup []netlist.Matcher

func (mg MatcherGroup) Match(addr netip.Addr) bool {
	for _, m := range mg {
		if m.Match(addr) {
			return true
		}
	}
	return false
}

type DynamicMatcherGroup struct {
	v *atomic.Value // MatcherGroup
}

func NewDynamicMatcherGroup() *DynamicMatcherGroup {
	d := &DynamicMatcherGroup{v: &atomic.Value{}}
	d.v.Store(MatcherGroup{})
	return d
}

func (d *DynamicMatcherGroup) Update(mg MatcherGroup) {
	d.v.Store(mg)
}

func (d *DynamicMatcherGroup) Match(addr netip.Addr) bool {
	return d.v.Load().(MatcherGroup).Match(addr)
}

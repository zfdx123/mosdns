package ngtip

import (
	"sync"
	"time"
)

type cacheItem struct {
	v bool
	t time.Time
}

type Cache struct {
	ttl time.Duration
	m   map[string]cacheItem
	mu  sync.RWMutex
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl: ttl,
		m:   make(map[string]cacheItem),
	}
}

func (c *Cache) Get(k string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[k]
	if !ok || time.Now().After(v.t) {
		return false, false
	}
	return v.v, true
}

func (c *Cache) Set(k string, v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = cacheItem{
		v: v,
		t: time.Now().Add(c.ttl),
	}
}

func (c *Cache) Delete(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
}

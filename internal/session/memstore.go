package session

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// DefaultMaxEntries bounds each in-memory store.
const DefaultMaxEntries = 10000

// DefaultSweepInterval is how often expired entries are purged.
const DefaultSweepInterval = time.Minute

// memStore is a bounded map with per-entry expiry. When full, the oldest
// entry is evicted (entries share a TTL, so oldest = closest to expiry).
// Expired entries are never returned, and are purged by Sweep.
type memStore[V any] struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	items map[string]*list.Element
	order *list.List // of *memEntry[V]; front = oldest
}

type memEntry[V any] struct {
	key     string
	val     V
	expires time.Time
}

func newMemStore[V any](maxEntries int, now func() time.Time) *memStore[V] {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &memStore[V]{max: maxEntries, now: now, items: map[string]*list.Element{}, order: list.New()}
}

// put stores v and reports how many entries were evicted to make room.
func (s *memStore[V]) put(key string, v V, expires time.Time) (evicted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.order.Remove(el)
		delete(s.items, key)
	}
	for s.order.Len() >= s.max {
		front := s.order.Front()
		s.order.Remove(front)
		delete(s.items, front.Value.(*memEntry[V]).key)
		evicted++
	}
	s.items[key] = s.order.PushBack(&memEntry[V]{key: key, val: v, expires: expires})
	return evicted
}

func (s *memStore[V]) lookup(key string, remove bool) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero V
	el, ok := s.items[key]
	if !ok {
		return zero, false
	}
	e := el.Value.(*memEntry[V])
	expired := !s.now().Before(e.expires)
	if remove || expired {
		s.order.Remove(el)
		delete(s.items, key)
	}
	if expired {
		return zero, false
	}
	return e.val, true
}

func (s *memStore[V]) get(key string) (V, bool)  { return s.lookup(key, false) }
func (s *memStore[V]) take(key string) (V, bool) { return s.lookup(key, true) }

func (s *memStore[V]) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.order.Remove(el)
		delete(s.items, key)
	}
}

// sweep removes expired entries and returns how many were removed.
func (s *memStore[V]) sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for el := s.order.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*memEntry[V]); !now.Before(e.expires) {
			s.order.Remove(el)
			delete(s.items, e.key)
			n++
		}
		el = next
	}
	return n
}

func (s *memStore[V]) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// runSweeper calls sweep every interval until ctx is done.
func runSweeper(ctx context.Context, interval time.Duration, sweep func() int) {
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

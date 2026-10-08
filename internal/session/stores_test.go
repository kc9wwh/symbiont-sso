package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestPendingStoreSingleUseAndExpiry(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := NewMemoryPendingStore(MemoryOptions{TTL: 10 * time.Minute, Now: clk.now})

	_ = st.Put(ctx, "s1", Pending{Kind: KindSP, SPID: "a"})
	p, err := st.Take(ctx, "s1")
	if err != nil || p.SPID != "a" {
		t.Fatalf("Take = %+v, %v", p, err)
	}
	if _, err := st.Take(ctx, "s1"); err != ErrNotFound {
		t.Errorf("second Take err = %v, want ErrNotFound (single use)", err)
	}

	_ = st.Put(ctx, "s2", Pending{})
	clk.add(10 * time.Minute)
	if _, err := st.Take(ctx, "s2"); err != ErrNotFound {
		t.Errorf("expired Take err = %v", err)
	}
	if _, err := st.Take(ctx, "never"); err != ErrNotFound {
		t.Errorf("unknown Take err = %v", err)
	}
}

func TestPendingStoreBoundedEvictsOldest(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryPendingStore(MemoryOptions{MaxEntries: 3})
	for i := 0; i < 5; i++ {
		_ = st.Put(ctx, fmt.Sprint(i), Pending{SPID: fmt.Sprint(i)})
	}
	if st.Len() != 3 {
		t.Fatalf("Len = %d, want 3", st.Len())
	}
	for _, k := range []string{"0", "1"} {
		if _, err := st.Take(ctx, k); err != ErrNotFound {
			t.Errorf("oldest entry %s not evicted", k)
		}
	}
	for _, k := range []string{"2", "3", "4"} {
		if _, err := st.Take(ctx, k); err != nil {
			t.Errorf("entry %s missing", k)
		}
	}
}

func TestDefaultBoundIs10k(t *testing.T) {
	st := NewMemoryPendingStore(MemoryOptions{})
	for i := 0; i < DefaultMaxEntries+5; i++ {
		_ = st.Put(context.Background(), fmt.Sprint(i), Pending{})
	}
	if st.Len() != DefaultMaxEntries || DefaultMaxEntries != 10000 {
		t.Errorf("Len = %d", st.Len())
	}
}

func TestSessionStore(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := NewMemorySessionStore(MemoryOptions{MaxEntries: 2, Now: clk.now})
	mk := func(id string, ttl time.Duration) Session {
		return Session{ID: id, Email: id + "@example.com", ExpiresAt: clk.now().Add(ttl)}
	}
	if err := st.Create(ctx, Session{}); err == nil {
		t.Error("empty ID accepted")
	}
	_ = st.Create(ctx, mk("a", time.Minute))
	got, err := st.Get(ctx, "a")
	if err != nil || got.Email != "a@example.com" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, err := st.Get(ctx, "a"); err != nil {
		t.Error("Get must not consume the session")
	}

	_ = st.Create(ctx, mk("b", time.Minute))
	_ = st.Create(ctx, mk("c", time.Minute)) // evicts a
	if _, err := st.Get(ctx, "a"); err != ErrNotFound {
		t.Errorf("evicted session still present: %v", err)
	}

	_ = st.Delete(ctx, "b")
	if _, err := st.Get(ctx, "b"); err != ErrNotFound {
		t.Errorf("deleted session present")
	}

	clk.add(time.Minute)
	if _, err := st.Get(ctx, "c"); err != ErrNotFound {
		t.Errorf("expired session returned")
	}
}

func TestSweep(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := NewMemoryPendingStore(MemoryOptions{TTL: time.Minute, Now: clk.now})
	_ = st.Put(ctx, "old", Pending{})
	clk.add(30 * time.Second)
	_ = st.Put(ctx, "new", Pending{})
	clk.add(31 * time.Second)
	if n := st.Sweep(); n != 1 || st.Len() != 1 {
		t.Errorf("Sweep removed %d, Len = %d", n, st.Len())
	}
	ss := NewMemorySessionStore(MemoryOptions{Now: clk.now})
	_ = ss.Create(ctx, Session{ID: "x", ExpiresAt: clk.now()})
	if n := ss.Sweep(); n != 1 || ss.Len() != 0 {
		t.Errorf("session Sweep removed %d", n)
	}
}

func TestRunSweeperStopsOnCancel(t *testing.T) {
	st := NewMemoryPendingStore(MemoryOptions{TTL: time.Nanosecond})
	_ = st.Put(context.Background(), "x", Pending{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { st.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for st.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if st.Len() != 0 {
		t.Error("sweeper did not purge")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper did not stop")
	}
}

func TestStoresConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryPendingStore(MemoryOptions{MaxEntries: 100})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				k := fmt.Sprintf("%d-%d", g, i)
				_ = st.Put(ctx, k, Pending{})
				_, _ = st.Take(ctx, k)
				st.Sweep()
			}
		}(g)
	}
	wg.Wait()
}

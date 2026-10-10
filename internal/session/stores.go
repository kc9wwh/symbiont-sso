package session

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned for missing, expired, evicted, or already-used
// entries.
var ErrNotFound = errors.New("session: not found or expired")

// ErrStoreFull is returned when a store refuses a new entry because it holds
// its maximum number of live entries.
var ErrStoreFull = errors.New("session: store is full")

// DefaultPendingMaxEntries bounds in-flight logins. Unlike sessions, pending
// logins are created by unauthenticated requests, so a full store rejects new
// logins instead of evicting logins that are already in progress.
const DefaultPendingMaxEntries = 5000

// Kind identifies which flow started a pending login.
type Kind string

// Pending login kinds.
const (
	KindSP  Kind = "sp"  // SP-initiated: replay the AuthnRequest to /sso
	KindIDP Kind = "idp" // IdP-initiated: return to /login/{sp_id}
)

// Pending is an in-flight upstream OIDC login, keyed by its OAuth state.
type Pending struct {
	Kind Kind
	SPID string
	// RawRequest is the decoded AuthnRequest XML (KindSP only).
	RawRequest []byte
	RelayState string
	// ForceLogin asks the upstream provider to re-authenticate the user
	// (the SP sent ForceAuthn="true").
	ForceLogin bool
	// ReceivedAt is when the AuthnRequest first arrived; replays are judged
	// at this time.
	ReceivedAt   time.Time
	PKCEVerifier string
	Nonce        string
	CreatedAt    time.Time
}

// PendingStore holds pending logins. Take is single-use: a state can be
// redeemed at most once.
type PendingStore interface {
	Put(ctx context.Context, state string, p Pending) error
	Take(ctx context.Context, state string) (Pending, error)
}

// Session is a signed-in user's identity. It deliberately holds identity
// only: access policy and attribute mapping are evaluated per service
// provider whenever an assertion is issued. Values must be treated as
// immutable by callers.
type Session struct {
	ID       string
	Subject  string
	Email    string
	Name     string
	Groups   []string
	Claims   map[string]any // only claims needed by mapping rules
	AuthTime time.Time
	// IssuedAt is when the bridge session was created.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionStore holds bridge sessions by ID.
type SessionStore interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, id string) (Session, error)
	Delete(ctx context.Context, id string) error
}

// MemoryOptions configures an in-memory store.
type MemoryOptions struct {
	// TTL is the lifetime of pending entries (sessions carry their own
	// ExpiresAt).
	TTL        time.Duration
	MaxEntries int
	Now        func() time.Time
}

// MemoryPendingStore is a bounded in-memory PendingStore.
type MemoryPendingStore struct {
	s   *memStore[Pending]
	ttl time.Duration
}

var _ PendingStore = (*MemoryPendingStore)(nil)

// NewMemoryPendingStore returns an empty store.
func NewMemoryPendingStore(o MemoryOptions) *MemoryPendingStore {
	if o.TTL <= 0 {
		o.TTL = 10 * time.Minute
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultPendingMaxEntries
	}
	return &MemoryPendingStore{s: newMemStore[Pending](o.MaxEntries, o.Now), ttl: o.TTL}
}

// Put implements PendingStore.
func (m *MemoryPendingStore) Put(_ context.Context, state string, p Pending) error {
	if !m.s.tryPut(state, p, m.s.now().Add(m.ttl)) {
		return ErrStoreFull
	}
	return nil
}

// Take implements PendingStore.
func (m *MemoryPendingStore) Take(_ context.Context, state string) (Pending, error) {
	p, ok := m.s.take(state)
	if !ok {
		return Pending{}, ErrNotFound
	}
	return p, nil
}

// Sweep purges expired entries.
func (m *MemoryPendingStore) Sweep() int { return m.s.sweep() }

// Len reports the number of stored entries (including not-yet-swept
// expired ones).
func (m *MemoryPendingStore) Len() int { return m.s.len() }

// Run sweeps periodically until ctx is done.
func (m *MemoryPendingStore) Run(ctx context.Context, interval time.Duration) {
	runSweeper(ctx, interval, m.Sweep)
}

// MemorySessionStore is a bounded in-memory SessionStore.
type MemorySessionStore struct {
	s *memStore[Session]
}

var _ SessionStore = (*MemorySessionStore)(nil)

// NewMemorySessionStore returns an empty store. o.TTL is unused.
func NewMemorySessionStore(o MemoryOptions) *MemorySessionStore {
	return &MemorySessionStore{s: newMemStore[Session](o.MaxEntries, o.Now)}
}

// Create implements SessionStore.
func (m *MemorySessionStore) Create(_ context.Context, s Session) error {
	if s.ID == "" {
		return errors.New("session: empty session ID")
	}
	m.s.put(s.ID, s, s.ExpiresAt)
	return nil
}

// Get implements SessionStore.
func (m *MemorySessionStore) Get(_ context.Context, id string) (Session, error) {
	s, ok := m.s.get(id)
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

// Delete implements SessionStore.
func (m *MemorySessionStore) Delete(_ context.Context, id string) error {
	m.s.delete(id)
	return nil
}

// Sweep purges expired sessions.
func (m *MemorySessionStore) Sweep() int { return m.s.sweep() }

// Len reports the number of stored sessions.
func (m *MemorySessionStore) Len() int { return m.s.len() }

// Run sweeps periodically until ctx is done.
func (m *MemorySessionStore) Run(ctx context.Context, interval time.Duration) {
	runSweeper(ctx, interval, m.Sweep)
}

package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunServesAndShutsDownGracefully(t *testing.T) {
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	s := New(Options{Logger: logger, ShutdownTimeout: 5 * time.Second})

	// Add a slow route to prove in-flight requests complete during shutdown.
	release := make(chan struct{})
	inFlight := make(chan struct{})
	mux := http.NewServeMux()
	s.routes(mux)
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(inFlight)
		<-release
		_, _ = io.WriteString(w, "done")
	})
	s.handler = s.middleware(mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx, ln) }()

	// No keep-alives: with a pooled transport, the /slow request can race a
	// fresh dial against the /healthz connection returning to the idle pool.
	// The losing dial is accepted but never sends a request, and Shutdown
	// treats such StateNew connections as active for 5s, which exceeds the
	// ShutdownTimeout above and fails the test intermittently.
	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	resp, err := client.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}

	slowBody := make(chan string, 1)
	go func() {
		r, err := client.Get(base + "/slow")
		if err != nil {
			slowBody <- "error: " + err.Error()
			return
		}
		defer func() { _ = r.Body.Close() }()
		b, _ := io.ReadAll(r.Body)
		slowBody <- string(b)
	}()
	<-inFlight
	cancel() // begin shutdown with a request in flight

	select {
	case err := <-runErr:
		t.Fatalf("Run returned before in-flight request finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	if got := <-slowBody; got != "done" {
		t.Errorf("in-flight request body = %q, want done", got)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
	if !strings.Contains(logs.String(), "http server stopped") {
		t.Errorf("missing shutdown log: %s", logs.String())
	}
	if r, err := client.Get(base + "/healthz"); err == nil {
		_ = r.Body.Close()
		t.Errorf("server still accepting connections after shutdown")
	}
}

func TestRunShutdownTimeoutForcesClose(t *testing.T) {
	s, _ := newTestServer(t, slog.LevelInfo)
	s.opts.ShutdownTimeout = 50 * time.Millisecond

	inFlight := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hang", func(http.ResponseWriter, *http.Request) {
		close(inFlight)
		<-release
	})
	s.handler = mux

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx, ln) }()
	go func() {
		if r, err := http.Get("http://" + ln.Addr().String() + "/hang"); err == nil {
			_ = r.Body.Close()
		}
	}()
	<-inFlight
	cancel()

	select {
	case err := <-runErr:
		if err == nil || !strings.Contains(err.Error(), "graceful shutdown") {
			t.Fatalf("want graceful shutdown timeout error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not honour ShutdownTimeout")
	}
}

func TestRunReturnsServeError(t *testing.T) {
	s, _ := newTestServer(t, slog.LevelInfo)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Serve fails immediately on a closed listener
	if err := s.Run(context.Background(), ln); err == nil {
		t.Fatal("expected error from closed listener")
	}
}

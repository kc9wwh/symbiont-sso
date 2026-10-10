package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteKeyPairForceDoesNotFollowPredictableTempPath(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An attacker-planted symlink at the old predictable temp name.
	if err := os.Symlink(victim, keyPath+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyPair(keyPath, []byte("KEY"), certPath, []byte("CERT"), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("symlink target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "KEY" {
		t.Errorf("key = %q", b)
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 600", st.Mode().Perm())
	}
	if st, _ := os.Stat(certPath); st.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %o, want 644", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "k.pem" && e.Name() != "c.pem" && e.Name() != "victim" && e.Name() != "k.pem.tmp" {
			t.Errorf("stray file left behind: %s", e.Name())
		}
	}
}

func TestWriteKeyPairForceFailureLeavesOriginalsIntact(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(keyPath, []byte("OLDKEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cert directory does not exist: staging the cert fails before anything is replaced.
	err := writeKeyPair(keyPath, []byte("NEWKEY"), filepath.Join(dir, "missing", "c.pem"), []byte("CERT"), true)
	if err == nil {
		t.Fatal("expected error")
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "OLDKEY" {
		t.Errorf("key replaced despite failure: %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestWriteKeyPairWithoutForceRollsBackKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	err := writeKeyPair(keyPath, []byte("KEY"), filepath.Join(dir, "missing", "c.pem"), []byte("CERT"), false)
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Errorf("orphaned key left behind (lstat err = %v)", err)
	}
}

func TestSyncDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directories cannot be synced on windows")
	}
	if err := syncDir(t.TempDir()); err != nil {
		t.Errorf("syncDir(existing) = %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("syncDir(missing) succeeded")
	}
}

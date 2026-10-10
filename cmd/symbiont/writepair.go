package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	keyFileMode  os.FileMode = 0o600
	certFileMode os.FileMode = 0o644
)

// writeKeyPair writes the private key and certificate so that a failure never
// leaves a mismatched pair or a key readable by others.
//
// Without overwrite, both files are created exclusively (O_EXCL: no
// symlink-following, no clobbering) and the key is removed again if the
// certificate cannot be written. With overwrite, both are staged in private
// temp files next to their targets and only then renamed into place, so the
// only window for a mismatch is between the two renames.
func writeKeyPair(keyPath string, keyPEM []byte, certPath string, certPEM []byte, overwrite bool) error {
	if !overwrite {
		return createKeyPair(keyPath, keyPEM, certPath, certPEM)
	}
	keyTmp, err := stageFile(keyPath, keyPEM, keyFileMode)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	certTmp, err := stageFile(certPath, certPEM, certFileMode)
	if err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(certTmp)
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("write key: %w (the certificate was already replaced and no longer matches the old key; re-run with --force)", err)
	}
	return syncDirs(keyPath, certPath)
}

func createKeyPair(keyPath string, keyPEM []byte, certPath string, certPEM []byte) error {
	if err := createExclusive(keyPath, keyPEM, keyFileMode); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := createExclusive(certPath, certPEM, certFileMode); err != nil {
		_ = os.Remove(keyPath)
		return fmt.Errorf("write certificate: %w", err)
	}
	return syncDirs(keyPath, certPath)
}

func createExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// syncDirs makes the directory entries of the written files durable, so a
// crash right after gencert reports success cannot lose the new names.
func syncDirs(paths ...string) error {
	seen := map[string]bool{}
	for _, p := range paths {
		d := filepath.Dir(p)
		if seen[d] {
			continue
		}
		seen[d] = true
		if err := syncDir(d); err != nil {
			return fmt.Errorf("files written but not durably recorded: %w", err)
		}
	}
	return nil
}

// syncDir fsyncs a directory. Windows cannot sync directories, so it is a
// no-op there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	return d.Close()
}

// stageFile writes data to a fresh temp file in path's directory (created
// 0600 by os.CreateTemp, so key bytes are never readable by others), sets
// mode, syncs, and returns the temp path.
func stageFile(path string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

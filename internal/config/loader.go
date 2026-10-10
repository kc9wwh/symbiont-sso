package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// loader accumulates problems and warnings while reading variables. Helper
// methods always return a usable zero value so loading can continue and
// report every problem at once.
type loader struct {
	lookup   LookupFunc
	now      func() time.Time
	problems []string
	warnings []string
}

func (l *loader) problemf(format string, args ...any) {
	l.problems = append(l.problems, fmt.Sprintf(format, args...))
}

func (l *loader) warnf(format string, args ...any) {
	l.warnings = append(l.warnings, fmt.Sprintf(format, args...))
}

func (l *loader) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// get returns the trimmed value of key. Variables set to an empty string are
// treated as unset, which matches how docker-compose renders "KEY=".
func (l *loader) get(key string) (string, bool) {
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

func (l *loader) str(key, def string) string {
	if v, ok := l.get(key); ok {
		return v
	}
	return def
}

func (l *loader) required(key string) string {
	v, ok := l.get(key)
	if !ok {
		l.problemf("%s is required", key)
	}
	return v
}

func (l *loader) boolean(key string, def bool) bool {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.problemf("%s must be a boolean (true/false), got %q", key, v)
		return def
	}
	return b
}

func (l *loader) nonNegativeInt(key string, def int) int {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		l.problemf("%s must be a non-negative integer (0 disables), got %q", key, v)
		return def
	}
	return n
}

func (l *loader) positiveDuration(key string, def time.Duration) time.Duration {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.problemf("%s must be a Go duration such as 60s or 10m, got %q", key, v)
		return def
	}
	if d <= 0 {
		l.problemf("%s must be greater than zero, got %q", key, v)
		return def
	}
	return d
}

// rawSecret resolves key or key_FILE. It reports a problem when both are set
// and never includes secret material in messages. The second return value is
// the name of the variable the value came from (for error messages).
func (l *loader) rawSecret(key string) ([]byte, string, bool) {
	fileKey := key + FileSuffix
	direct, hasDirect := l.get(key)
	path, hasFile := l.get(fileKey)

	switch {
	case hasDirect && hasFile:
		l.problemf("%s and %s are mutually exclusive; set only one", key, fileKey)
		return nil, key, false
	case hasDirect:
		return []byte(direct), key, true
	case hasFile:
		b, err := readLimited(path, maxSecretFileBytes)
		if err != nil {
			l.problemf("%s: cannot read secret file: %v", fileKey, err)
			return nil, fileKey, false
		}
		b = []byte(strings.TrimSpace(string(b)))
		if len(b) == 0 {
			l.problemf("%s: secret file %q is empty", fileKey, path)
			return nil, fileKey, false
		}
		return b, fileKey, true
	default:
		return nil, key, false
	}
}

// requiredSecret resolves a mandatory secret. If rawSecret already reported
// a specific problem (unreadable file, both forms set) no redundant
// "is required" message is added.
func (l *loader) requiredSecret(key string) Secret {
	b, _, ok := l.requiredRawSecret(key)
	if !ok {
		return Secret{}
	}
	return NewSecret(b)
}

func (l *loader) requiredRawSecret(key string) ([]byte, string, bool) {
	before := len(l.problems)
	b, src, ok := l.rawSecret(key)
	if !ok && len(l.problems) == before {
		l.problemf("%s (or %s%s) is required", key, key, FileSuffix)
	}
	return b, src, ok
}

// readableFile checks that key names an existing, readable regular file.
func (l *loader) readableFile(key string) string {
	path, ok := l.get(key)
	if !ok {
		l.problemf("%s is required", key)
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		l.problemf("%s: cannot open %q: %v", key, path, unwrapPathErr(err))
		return path
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		l.problemf("%s: cannot stat %q: %v", key, path, unwrapPathErr(err))
		return path
	}
	if !st.Mode().IsRegular() {
		l.problemf("%s: %q is not a regular file", key, path)
	}
	return path
}

// readLimited reads at most limit bytes from path, failing if it is larger.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, unwrapPathErr(err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, unwrapPathErr(err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file %q exceeds %d bytes", path, limit)
	}
	return b, nil
}

// unwrapPathErr keeps messages short: *fs.PathError already carries the
// path, which callers print themselves.
func unwrapPathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func (l *loader) checkRemovedVars() {
	keys := make([]string, 0, len(removedVars))
	for k := range removedVars {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if _, ok := l.lookup(k); ok {
			l.warnf("%s is no longer used (%s); it is being ignored", k, removedVars[k])
		}
	}
}

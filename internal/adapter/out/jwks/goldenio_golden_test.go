package jwks

// Golden-vector I/O (AUTH-027). This file is copied verbatim (only the package
// clause differs) into every package that emits golden vectors, because the
// golden write scope is limited to *_golden_test.go files. Keep the copies in
// sync; see testdata/golden/README.md.
//
// Each area file testdata/golden/<area>.json is a JSON object of named
// sections. A section is owned by exactly one Go package. Verify mode (the
// default) fails when the freshly computed section differs from the file;
// GOLDEN_UPDATE=1 rewrites the section instead.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const goldenUpdateEnv = "GOLDEN_UPDATE"

func goldenUpdating() bool {
	return os.Getenv(goldenUpdateEnv) == "1"
}

// goldenRoot returns <repo>/testdata/golden by walking up to go.mod.
func goldenRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("golden: getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "golden")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("golden: go.mod not found above working directory")
		}
		dir = parent
	}
}

// goldenReadFile reads a file relative to testdata/golden.
func goldenReadFile(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("golden: read %s: %v", rel, err)
	}
	return raw
}

// goldenJSON encodes v compactly without HTML escaping, so strings in the
// vector files read exactly as the Go values they record.
func goldenJSON(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("golden: encode: %v", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// goldenSection verifies (or with GOLDEN_UPDATE=1 writes) one section of
// testdata/golden/<area>.json.
func goldenSection(t *testing.T, area, section string, value any) {
	t.Helper()
	path := filepath.Join(goldenRoot(t), area+".json")
	fresh := goldenJSON(t, value)

	if goldenUpdating() {
		unlock := goldenLock(t, path+".lock")
		defer unlock()
		doc := map[string]json.RawMessage{}
		existing, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(existing, &doc); err != nil {
				t.Fatalf("golden: parse %s: %v", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			t.Fatalf("golden: read %s: %v", path, err)
		}
		doc[section] = fresh
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			t.Fatalf("golden: encode %s: %v", path, err)
		}
		if bytes.Equal(existing, buf.Bytes()) {
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("golden: mkdir: %v", err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("golden: write %s: %v", path, err)
		}
		return
	}

	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden: read %s: %v (regenerate with %s=1 go test ./... -run Golden -count=1)", path, err, goldenUpdateEnv)
	}
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(existing, &doc); err != nil {
		t.Fatalf("golden: parse %s: %v", path, err)
	}
	stored, ok := doc[section]
	if !ok {
		t.Fatalf("golden: %s has no section %q (regenerate with %s=1 go test ./... -run Golden -count=1)", path, section, goldenUpdateEnv)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, stored); err != nil {
		t.Fatalf("golden: compact %s/%s: %v", area, section, err)
	}
	if !bytes.Equal(want.Bytes(), fresh) {
		t.Fatalf("golden: %s.json section %q no longer matches Go behavior.\n%s\nIf the change is intended, regenerate with %s=1 go test ./... -run Golden -count=1 and review the diff.",
			area, section, goldenFirstDiff(want.Bytes(), fresh), goldenUpdateEnv)
	}
}

func goldenFirstDiff(want, got []byte) string {
	i := 0
	for i < len(want) && i < len(got) && want[i] == got[i] {
		i++
	}
	clip := func(b []byte) string {
		start := max(i-60, 0)
		end := min(i+120, len(b))
		if start > len(b) {
			return ""
		}
		return string(b[start:end])
	}
	return fmt.Sprintf("first difference at byte %d\n  file: ...%s...\n  go:   ...%s...", i, clip(want), clip(got))
}

// goldenLock serialises update-mode writers: `go test ./...` runs package
// test binaries in parallel and several packages share one area file.
func goldenLock(t *testing.T, path string) func() {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }
		}
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("golden: lock %s: %v", path, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("golden: timed out waiting for %s (remove it if a previous run was interrupted)", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// goldenHex is a helper for recording raw bytes next to their encodings.
func goldenHex(b []byte) string {
	return hex.EncodeToString(b)
}

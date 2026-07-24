package storage_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/itsalmirr/keystone/keylog"
	"github.com/itsalmirr/keystone/storage"
)

func mustOpen(t *testing.T, path string) *storage.FileStore {
	t.Helper()
	s, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return s
}

func mustAppend(t *testing.T, s *storage.FileStore, data string) int64 {
	t.Helper()
	idx, err := s.Append(context.Background(), []byte(data))
	if err != nil {
		t.Fatalf("Append(%q): %v", data, err)
	}
	return idx
}

// chainOf recomputes the expected head over the given payloads,
// independently of the store.
func chainOf(payloads ...string) tlog.Hash {
	var h tlog.Hash
	for _, p := range payloads {
		h = keylog.ChainHash(h, []byte(p))
	}
	return h
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.log")
	s := mustOpen(t, path)
	defer s.Close()

	if n, _ := s.Size(ctx); n != 0 {
		t.Fatalf("new log Size = %d, want 0", n)
	}

	payloads := []string{"alpha", "", "gamma"} // empty payload is legal
	for i, p := range payloads {
		if idx := mustAppend(t, s, p); idx != int64(i) {
			t.Fatalf("Append #%d returned index %d", i, idx)
		}
	}
	for i, p := range payloads {
		got, err := s.ReadLeaf(ctx, int64(i))
		if err != nil {
			t.Fatalf("ReadLeaf(%d): %v", i, err)
		}
		if !bytes.Equal(got, []byte(p)) {
			t.Fatalf("ReadLeaf(%d) = %q, want %q", i, got, p)
		}
	}
	if n, _ := s.Size(ctx); n != 3 {
		t.Fatalf("Size = %d, want 3", n)
	}
	if got := s.Head(); got != chainOf(payloads...) {
		t.Fatalf("Head = %x, want independent recompute %x", got, chainOf(payloads...))
	}

	for _, idx := range []int64{-1, 3, 99} {
		if _, err := s.ReadLeaf(ctx, idx); !errors.Is(err, storage.ErrOutOfRange) {
			t.Fatalf("ReadLeaf(%d) err = %v, want ErrOutOfRange", idx, err)
		}
	}
}

func TestReopenContinuesChain(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.log")

	s := mustOpen(t, path)
	mustAppend(t, s, "alpha")
	mustAppend(t, s, "beta")
	s.Close()

	s = mustOpen(t, path)
	if n, _ := s.Size(ctx); n != 2 {
		t.Fatalf("Size after reopen = %d, want 2", n)
	}
	mustAppend(t, s, "gamma")
	s.Close()

	s = mustOpen(t, path)
	defer s.Close()
	if got, want := s.Head(), chainOf("alpha", "beta", "gamma"); got != want {
		t.Fatalf("Head after reopen = %x, want %x", got, want)
	}
}

func TestTornTailIsTruncated(t *testing.T) {
	ctx := context.Background()
	for name, cut := range map[string]int64{
		"mid-chain-hash": 5,  // cuts into the last record's chain hash
		"mid-len-field":  39, // "gamma" frame is 41 bytes; leaves 2 bytes of len
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.log")
			s := mustOpen(t, path)
			mustAppend(t, s, "alpha")
			mustAppend(t, s, "beta")
			mustAppend(t, s, "gamma")
			s.Close()

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, info.Size()-cut); err != nil {
				t.Fatal(err)
			}

			s = mustOpen(t, path)
			defer s.Close()
			if n, _ := s.Size(ctx); n != 2 {
				t.Fatalf("Size after torn-tail recovery = %d, want 2", n)
			}
			if got, err := s.ReadLeaf(ctx, 1); err != nil || string(got) != "beta" {
				t.Fatalf("ReadLeaf(1) = %q, %v", got, err)
			}
			// The log must accept appends again after recovery.
			if idx := mustAppend(t, s, "delta"); idx != 2 {
				t.Fatalf("Append after recovery returned index %d, want 2", idx)
			}
			if got, want := s.Head(), chainOf("alpha", "beta", "delta"); got != want {
				t.Fatalf("Head after recovery = %x, want %x", got, want)
			}
		})
	}
}

func TestCorruptRecordFailsOpen(t *testing.T) {
	// Flipping a payload byte must fail open with the record's index —
	// including for the final record, which is never auto-truncated
	// (ADR-002: complete-frame mismatch is evidence, not a torn write).
	for name, tc := range map[string]struct {
		fromEnd   int64 // byte position relative to file end
		wantIndex int64
	}{
		"first-record": {fromEnd: 3*41 - 4 - 1, wantIndex: 0}, // each frame: 4+5+32 = 41 bytes
		"last-record":  {fromEnd: 41 - 4 - 1, wantIndex: 2},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.log")
			s := mustOpen(t, path)
			mustAppend(t, s, "alpha")
			mustAppend(t, s, "bravo")
			mustAppend(t, s, "gamma")
			s.Close()

			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			info, _ := f.Stat()
			pos := info.Size() - tc.fromEnd
			if _, err := f.WriteAt([]byte{0xFF}, pos); err != nil {
				t.Fatal(err)
			}
			f.Close()

			_, err = storage.Open(path)
			var ce *storage.CorruptError
			if !errors.As(err, &ce) {
				t.Fatalf("Open err = %v, want *CorruptError", err)
			}
			if ce.Index != tc.wantIndex {
				t.Fatalf("CorruptError.Index = %d, want %d", ce.Index, tc.wantIndex)
			}
		})
	}
}

func TestNotAKeystoneLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(path, []byte("definitely not a keystone log file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(path); err == nil {
		t.Fatal("Open of a foreign file succeeded, want error")
	}
}

func TestAppendRejectsOversizedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	s := mustOpen(t, path)
	defer s.Close()
	if _, err := s.Append(context.Background(), make([]byte, storage.MaxRecordSize+1)); err == nil {
		t.Fatal("Append over MaxRecordSize succeeded, want error")
	}
}

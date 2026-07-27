package storage_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/itsalmirr/keystone/keylog"
	"github.com/itsalmirr/keystone/storage"
)

// buildLog constructs a valid log file through the store and returns
// its raw bytes, for seeding the fuzzer with structurally valid input.
func buildLog(f *testing.F, payloads ...string) []byte {
	f.Helper()
	path := filepath.Join(f.TempDir(), "seed.log")
	s, err := storage.Open(path)
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range payloads {
		if _, err := s.Append(context.Background(), []byte(p)); err != nil {
			f.Fatal(err)
		}
	}
	s.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	return raw
}

// FuzzOpen throws arbitrary bytes at the record decoder. Open may
// reject the input, but it must never panic, and when it accepts, the
// resulting store must uphold the chain invariant and recover
// idempotently.
func FuzzOpen(f *testing.F) {
	valid := buildLog(f, "alpha", "beta", "gamma")
	f.Add([]byte{})
	f.Add(buildLog(f)) // bare header
	f.Add(valid)
	f.Add(valid[:len(valid)-5])                   // torn tail
	f.Add(append(bytes.Clone(valid), 0, 0, 0, 9)) // trailing garbage frame
	tampered := bytes.Clone(valid)
	tampered[20] ^= 0xFF // payload byte of record 0
	f.Add(tampered)

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "fuzz.log")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		s, err := storage.Open(path)
		if err != nil {
			return // rejection is fine; panics are not
		}

		// Invariant 1: every accepted record is readable and the head
		// equals an independent chain recompute over the leaves.
		n, err := s.Size(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var chain tlog.Hash
		end := int64(16) // header, pinned by TestGoldenLogFormat
		for i := int64(0); i < n; i++ {
			leaf, err := s.ReadLeaf(ctx, i)
			if err != nil {
				t.Fatalf("accepted log: ReadLeaf(%d): %v", i, err)
			}
			chain = keylog.ChainHash(chain, leaf)
			end += int64(4 + len(leaf) + 32)
		}
		if chain != s.Head() {
			t.Fatalf("accepted log: head %x != recomputed chain %x", s.Head(), chain)
		}
		// Invariant 1b: the on-disk size equals the recovered end — an
		// accepted log carries no stray bytes past its last record.
		if fi, err := os.Stat(path); err != nil || fi.Size() != end {
			t.Fatalf("on-disk size = %d (%v), want recovered end %d", fi.Size(), err, end)
		}
		s.Close()

		// Invariant 2: recovery is idempotent — a second Open sees the
		// same log and performs no further truncation.
		s2, err := storage.Open(path)
		if err != nil {
			t.Fatalf("reopen after accepted open failed: %v", err)
		}
		defer s2.Close()
		if n2, _ := s2.Size(ctx); n2 != n || s2.Head() != chain {
			t.Fatalf("recovery not idempotent: size %d→%d", n, n2)
		}
	})
}

// splitPayloads derives 1–4 record payloads deterministically from
// fuzz input.
func splitPayloads(seed []byte) [][]byte {
	k := 1 + len(seed)%4
	out := make([][]byte, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, seed[i*len(seed)/k:(i+1)*len(seed)/k])
	}
	return out
}

// FuzzRecovery owns the accept path that byte-mutation fuzzing cannot
// reach (a mutated complete frame always fails its chain hash): it
// builds a real log, cuts an arbitrary number of trailing bytes, and
// asserts ADR-002's recovery contract exactly — Open succeeds, every
// complete frame survives, the torn remainder is gone from disk, and
// the log accepts and persists appends again.
func FuzzRecovery(f *testing.F) {
	f.Add([]byte("alpha\xffbeta"), uint16(5))
	f.Add([]byte("a"), uint16(0))
	f.Add([]byte{}, uint16(200))
	f.Add([]byte("keystone"), uint16(41)) // cut exactly one frame
	f.Fuzz(func(t *testing.T, seed []byte, cutRaw uint16) {
		ctx := context.Background()
		payloads := splitPayloads(seed)
		path := filepath.Join(t.TempDir(), "fuzz.log")
		s, err := storage.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range payloads {
			if _, err := s.Append(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		s.Close()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cut := int(cutRaw) % (len(raw) + 1)
		if err := os.Truncate(path, int64(len(raw)-cut)); err != nil {
			t.Fatal(err)
		}

		// Every frame fully inside the kept prefix must survive; a cut
		// below the header means reinitialization to an empty log.
		keep := len(raw) - cut
		var (
			head tlog.Hash
			want int64
			end  = 16
		)
		for _, p := range payloads {
			next := end + 4 + len(p) + 32
			if next > keep {
				break
			}
			head = keylog.ChainHash(head, p)
			end = next
			want++
		}

		s, err = storage.Open(path)
		if err != nil {
			t.Fatalf("recovery Open (cut %d of %d) failed: %v", cut, len(raw), err)
		}
		if n, _ := s.Size(ctx); n != want || s.Head() != head {
			t.Fatalf("recovered %d records (head %x), want %d (%x)", n, s.Head(), want, head)
		}
		if fi, err := os.Stat(path); err != nil || fi.Size() != int64(end) {
			t.Fatalf("on-disk size after recovery = %d (%v), want %d", fi.Size(), err, end)
		}
		if _, err := s.Append(ctx, []byte("probe")); err != nil {
			t.Fatalf("append after recovery: %v", err)
		}
		s.Close()

		s, err = storage.Open(path)
		if err != nil {
			t.Fatalf("reopen after post-recovery append: %v", err)
		}
		defer s.Close()
		if n, _ := s.Size(ctx); n != want+1 {
			t.Fatalf("size after probe append = %d, want %d", n, want+1)
		}
		if got, err := s.ReadLeaf(ctx, want); err != nil || string(got) != "probe" {
			t.Fatalf("probe record = %q, %v", got, err)
		}
	})
}

// TestGoldenLogFormat locks the on-disk format: testdata/golden.log was
// built byte-by-byte by an independent Python implementation of
// ADR-002, so this test fails if framing, magic, or chain hashing ever
// drift from the spec.
func TestGoldenLogFormat(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile("testdata/golden.log")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "golden.log")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open(golden.log): %v", err)
	}
	defer s.Close()

	want := []string{"", "a", "alpha", "\x00", "\xff\x00\xff", "hello, transparency log"}
	if n, _ := s.Size(ctx); n != int64(len(want)) {
		t.Fatalf("Size = %d, want %d", n, len(want))
	}
	for i, p := range want {
		got, err := s.ReadLeaf(ctx, int64(i))
		if err != nil || string(got) != p {
			t.Fatalf("ReadLeaf(%d) = %q, %v; want %q", i, got, err, p)
		}
	}
	const wantHead = "7cc1ccafa2175609cab95db413f725bd6506b300a8ff5d07c274c583d1389ab5"
	head := s.Head()
	if got := hex.EncodeToString(head[:]); got != wantHead {
		t.Fatalf("Head = %s, want %s", got, wantHead)
	}
}

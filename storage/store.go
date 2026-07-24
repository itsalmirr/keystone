package storage

import (
	"context"
	"errors"

	"golang.org/x/mod/sumdb/tlog"
)

// ErrOutOfRange reports a read of a record index at or beyond the log's
// current size (or below zero).
var ErrOutOfRange = errors.New("storage: record index out of range")

// AppendStore is durable, ordered, append-only record storage — the
// effectful edge of a keystone log.
//
// Records are opaque byte strings identified by a dense, zero-based
// int64 index assigned at append time. Committed records are immutable;
// implementations must never rewrite, reorder, or drop them. Per
// ADR-001, the bytes returned by ReadLeaf are exactly the bytes given
// to Append: chain metadata such as the previous record's hash lives in
// the implementation's record framing, never inside the leaf itself.
type AppendStore interface {
	// Append commits data as the next record and returns the index it
	// was assigned. When Append returns nil, the record must survive a
	// crash; each implementation documents its fsync policy.
	Append(ctx context.Context, data []byte) (int64, error)

	// ReadLeaf returns the exact bytes committed at index.
	// It returns ErrOutOfRange if index is negative or >= Size.
	ReadLeaf(ctx context.Context, index int64) ([]byte, error)

	// Size returns the number of committed records.
	Size(ctx context.Context) (int64, error)
}

// HashReader is the read side a store grows to satisfy once the Merkle
// tree lands: hashes of tree nodes addressed by tlog's stored-hash
// numbering (see tlog.StoredHashIndex). It deliberately mirrors
// tlog.HashReader so that tlog.TreeHash, tlog.ProveRecord, and
// tlog.ProveTree run directly over a store with no adapter; the
// signature is therefore fixed by the upstream interface and carries no
// context — implementations that need one bind it at construction.
type HashReader interface {
	// ReadHashes returns the stored hash for each of the given
	// stored-hash indexes.
	ReadHashes(indexes []int64) ([]tlog.Hash, error)
}

// Compile-time guarantee that HashReader never drifts from the upstream
// shape: this assignment only type-checks while every HashReader is
// also a tlog.HashReader.
var _ tlog.HashReader = (HashReader)(nil)

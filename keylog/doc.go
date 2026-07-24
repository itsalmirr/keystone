// Package keylog implements the deterministic core of keystone: canonical
// record hashing and the append-only hash chain (a Merkle tree replaces
// the chain internals in a later phase).
//
// Invariant: this package performs no I/O and holds no effectful state.
// Everything in it is a pure function of its inputs, which keeps it
// trivially fuzzable and lets storage and transport evolve at the edges
// without touching hashing logic.
package keylog

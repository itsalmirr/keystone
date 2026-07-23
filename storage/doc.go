// Package storage provides durable persistence for keystone logs: the
// AppendStore interface and an append-only file implementation with
// torn-write recovery.
//
// All I/O lives here, behind interfaces, so the hashing core in package
// log stays deterministic and I/O-free.
package storage

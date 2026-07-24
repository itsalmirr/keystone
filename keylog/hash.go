package keylog

import (
	"crypto/sha256"

	"golang.org/x/mod/sumdb/tlog"
)

// Domain-separation prefixes from ADR-001's registry. 0x01 is reserved
// for Merkle interior nodes and lands with the tree in Aug 2026.
const (
	leafPrefix  = 0x00 // RFC 6962 leaf (ADR-001)
	chainPrefix = 0x02 // hash-chain link, framing-layer (ADR-002)
)

// LeafHash returns the canonical hash of a record's content:
// SHA-256(0x00 ‖ data). It is defined to be byte-identical to
// tlog.RecordHash; the two are implemented independently and tested for
// equality rather than one delegating to the other.
func LeafHash(data []byte) tlog.Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out tlog.Hash
	h.Sum(out[:0])
	return out
}

// ChainHash returns the chain link that commits to every record up to
// and including this one: SHA-256(0x02 ‖ prev ‖ LeafHash(data)). The
// first record's prev is the zero hash. Both inputs after the prefix
// are fixed-width, so the encoding is unambiguous without length
// prefixes (ADR-002).
func ChainHash(prev tlog.Hash, data []byte) tlog.Hash {
	leaf := LeafHash(data)
	h := sha256.New()
	h.Write([]byte{chainPrefix})
	h.Write(prev[:])
	h.Write(leaf[:])
	var out tlog.Hash
	h.Sum(out[:0])
	return out
}

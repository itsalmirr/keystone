# ADR-001: Canonical Serialization and Domain Separation

- Status: accepted
- Date: 2026-07-23

## Context

Every hash keystone writes must verify forever. The bytes that go into
the hash function are therefore the one decision that can never be
revisited: changing them invalidates every hash ever written and breaks
every retained head. This ADR fixes those bytes once, in writing,
before any hashing code exists.

Storage framing (record lengths, chain metadata, file headers) is *not*
covered here — it can evolve behind a format version. Only hashed
content is frozen.

## Decision

### 1. Hash function: SHA-256

32-byte digests, `crypto/sha256`. Chosen for compatibility with
RFC 6962 and `golang.org/x/mod/sumdb/tlog`, the ecosystem keystone
interoperates with. Hash agility is deliberately excluded: a log is
SHA-256 for its lifetime. If a break ever forces migration, that is a
new log format with new domain prefixes, not a renegotiation of this
one.

### 2. Domain separation from the first hash

```
leaf     = SHA-256(0x00 ‖ entry_bytes)
interior = SHA-256(0x01 ‖ left_hash ‖ right_hash)
```

This matches RFC 6962 §2.1 and is byte-identical to
`tlog.RecordHash` / `tlog.NodeHash`. The distinct prefixes make leaf
and interior hashes different functions, closing the classic
second-preimage confusion between "hash of data" and "hash of two
hashes" (the Bitcoin CVE-2012-2459 class of bug). Any future hashed
structure gets its own new prefix (0x02, …) — never a reused one.

### 3. Leaf content is the entry's raw bytes, nothing else

The hashed leaf is exactly the caller's entry bytes. No index, no
timestamp, no `prev_hash`, no framing. Chain metadata lives in the
storage record around the leaf, never inside it. Consequence: the
Aug 2026 Merkle tree hashes July's leaves byte-for-byte — the swap is
internal to `keylog/` with zero data migration.

### 4. Canonical encoding for any multi-field hashed structure

July's leaves are single opaque byte strings, so this rule is dormant
until a structured hashed object appears (e.g. a signed checkpoint).
When one does:

- fixed field order, defined in the ADR that introduces the structure;
- fixed-width integers, big-endian, via `encoding/binary`;
- variable-length fields prefixed with a big-endian `uint64` length;
- no JSON, no maps, no floats, no reflection-based encoders anywhere
  in the hashed path. Map iteration order and float formatting are
  non-canonical by construction; they are excluded categorically
  rather than worked around.

### 5. Enforcement

Golden known-answer vectors in `testdata/` pin these bytes, and a
property test asserts keystone's roots equal `tlog.TreeHash` over
identical random leaves. Compatibility with `sumdb/tlog` is a tested
invariant, not an intention.

## Alternatives considered

- **Canonical JSON (JCS, RFC 8785):** rejected — pulls float and
  string-escaping subtleties into the hashed path for no benefit over
  length-prefixed binary.
- **Protobuf deterministic marshaling:** rejected — explicitly not
  canonical across library versions or languages per its own docs.
- **Canonical CBOR:** rejected — a dependency and a spec surface far
  larger than the problem.
- **SHA-512/256 or BLAKE3:** rejected — faster, but forfeits
  RFC 6962 / `sumdb/tlog` interoperability, which is the point.

## Consequences

- `keylog/` hashing is implementable directly against `sumdb/tlog`
  helpers, and October's tile storage reuses the same hashes.
- Changing anything in this document is defined as creating a new,
  incompatible log format. There is no in-place migration path, by
  design.

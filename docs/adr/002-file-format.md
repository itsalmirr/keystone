# ADR-002: Append-Only File Format and Recovery Policy

- Status: accepted
- Date: 2026-07-23

## Context

July's store is a single append-only file per log. ADR-001 froze only
the hashed leaf bytes; everything in this document — framing, chain
metadata, limits, durability — is framing-layer and may evolve behind
the format version in the file header (October's tile storage will
replace it wholesale). The requirements: return leaf bytes byte-exactly,
survive torn writes, make post-hoc modification detectable, and never
silently discard a committed record.

## Decision

### Layout

```
file   := header record*
header := "keystone-log-v1\n"                     (16 bytes, ASCII)
record := len(uint32, big-endian) payload chain   (chain: 32 bytes)
```

- `len` is the payload length. `MaxRecordSize` is 16 MiB — generous for
  audit entries, small enough that a corrupt length field cannot force
  a pathological allocation. Raising it later is compatible; lowering
  it is not.
- `payload` is the leaf: exactly the bytes passed to `Append`
  (ADR-001 — no metadata inside).
- `chain` is the running chain hash after this record:
  `chain_i = SHA-256(0x02 ‖ chain_{i-1} ‖ leaf_i)` with
  `chain_{-1} = 0^32` and `leaf_i` per ADR-001. `0x02` is allocated
  from ADR-001's domain-prefix registry; the chain is framing-layer and
  is superseded by the Merkle tree (Aug 2026), while leaves carry
  forward unchanged.
- Log files are created with mode 0600.

### Durability

- Each record is one `write(2)` on an `O_APPEND` descriptor, followed
  by `fsync` before `Append` returns — the batch size is one.
  Tradeoff: an fsync per record caps throughput at the disk's flush
  rate; the accepted lever if that becomes limiting is group commit
  (batching appends per fsync), to be justified with `BenchmarkAppend`
  numbers rather than adopted speculatively.
- The parent directory is fsynced when a log file is created, so the
  file itself survives a crash immediately after creation.
- Fail-stop: after any write or fsync error the store refuses further
  appends (reads still work). Reopening runs recovery.

### Recovery on open — forward scan, validate, truncate

| Observation | Classification | Action |
|---|---|---|
| File empty, or contents are a proper prefix of the header | new log, or torn creation | (re)write header |
| First 16 bytes ≠ header | not a keystone log | fail open |
| Incomplete final frame (`len` field or payload+chain cut short) | torn append — was never acknowledged | truncate to last complete record, fsync |
| `len` > MaxRecordSize | corruption (no such frame is ever legally written) | fail open with CorruptError |
| Complete frame, chain hash mismatch | corruption or tampering | fail open with CorruptError carrying the record index |

The asymmetry in the last two rows is deliberate. An incomplete frame
can only be the residue of an `Append` that never returned success —
`Append` fsyncs before acknowledging — so truncating it can never
destroy a committed record. A *complete* frame with a bad hash is
ambiguous: a crash between `write` and `fsync` can leave a full-length
frame with garbage content (sector writes are unordered), but the same
observation is produced by tampering with the final record. We fail
loudly and leave the bytes in place rather than auto-truncate, because
destroying possible evidence to regain availability is the wrong
default for a tamper-evident log. Manual truncation (or a future
`keystone repair` command) is the operator's escape hatch.

### Alternatives considered

- **SQLite or an embedded KV store:** durability and atomicity for
  free, but it hides exactly the byte-level discipline this store
  exists to demonstrate, and adds a heavyweight dependency. Rejected.
- **Separate WAL + data file:** two files to keep consistent with no
  benefit at this scale; tile storage restructures persistence in
  October anyway. Rejected.
- **Per-record CRC alongside the chain hash:** redundant — the chain
  hash detects everything a CRC would, and an adversary defeats both
  the same way. Rejected.

## Consequences

- Open is O(file): a full forward scan recomputing the chain. That
  doubles as free verification — a store that opens cleanly has a
  self-consistent chain. Acceptable at July scale; October replaces it.
- An in-memory offset index (8 bytes/record) provides random-access
  `ReadLeaf`.
- `ReadLeaf` trusts open-time validation and does not re-verify per
  read; verification is an explicit operation (the `verify` command
  re-scans from disk).

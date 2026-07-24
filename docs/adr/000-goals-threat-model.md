# ADR-000: Goals, Non-Goals, and Threat Model (v1)

- Status: accepted
- Date: 2026-07-23

## Context

Keystone is a tamper-evident, append-only log: a Go library (`keylog/`,
`storage/`) and a CLI (`keystone`). It records opaque byte entries and
lets a verifier detect after the fact whether committed entries were
modified, deleted, or reordered.

The July 2026 milestone is a hash-chained log over an append-only file
store with a scriptable `verify` command. The internals evolve on a
fixed roadmap — Merkle tree (Aug 2026), network API (Sep 2026), tile
storage at scale (Oct 2026), signed checkpoints and witnessing hooks
(Dec 2026) — so this document records what keystone promises, what it
deliberately does not, and against whom. Scope changes land here first.

## Goals

1. **Tamper evidence.** Detect post-hoc modification, deletion
   (including truncation), and reordering of any committed entry.
2. **Deterministic verification.** Identical entries always produce
   identical hashes on every platform. Canonical serialization and
   domain separation are fixed in ADR-001 and match RFC 6962 /
   `sumdb/tlog`, so proofs interoperate with existing transparency-log
   tooling.
3. **Crash safety.** An append interrupted by crash or power loss never
   corrupts committed entries; on open, the store recovers to the last
   complete record.
4. **Scriptable verification.** `keystone verify` exits 0 on a clean
   log, 1 on detected tampering (printing the first failing index), and
   2 on operational error. This contract is frozen; automation may
   depend on it.
5. **Embeddability.** Core packages are importable by other projects
   (Isobar is the first consumer), so they live outside `internal/` and
   keep effect-free, interface-based seams.

## Non-Goals (v1)

- **Split-view (equivocation) prevention.** A log operator can show
  different, individually consistent logs to different verifiers.
  Preventing that requires signed checkpoints gossiped through external
  witnesses — planned for Dec 2026, out of scope now.
- **Tamper *proofing*.** An attacker who controls storage can destroy
  or rewrite bytes; keystone guarantees detection, not prevention or
  recovery. Tamper-evident ≠ tamper-proof.
- **Confidentiality and access control.** Entries are stored in
  plaintext; protecting them is the deployment's job.
- **Multi-writer coordination.** One writer per log. Concurrent readers
  are fine.
- **High availability and replication.** Durability policy is a single
  fsync'd file (ADR to accompany the store implementation).

## Threat Model v1

**Adversary:** an insider with write access to the log's storage — a
malicious or compromised operator, or anyone with the disk. They can
rewrite, delete, reorder, truncate, or re-append records at rest, at
any time after commit.

**Verifier's trust anchor:** a previously observed log head retained
out of band (or exchanged with another verifier). Verification compares
the current log against that head.

| Attack | Outcome |
|--------|---------|
| Modify a committed entry's bytes | Detected: hash mismatch at that index |
| Delete or truncate committed entries | Detected: log shorter than, or inconsistent with, the retained head |
| Reorder committed entries | Detected: chain/root mismatch |
| Append new valid entries | Allowed — the log is append-only by design |
| Rewrite the entire log from genesis | Detected only against a retained prior head; a verifier with no prior head learns internal consistency only |
| Show different logs to different verifiers (split view) | Not detected in v1 — requires external witnessing (Dec 2026) |
| Destroy the log wholesale | Out of scope: detection of loss, not prevention |

## Consequences

- The hashed leaf content contains entry bytes only; chain metadata
  lives in record framing so the Aug 2026 Merkle swap consumes July's
  leaves byte-for-byte (ADR-001).
- `keylog/` stays deterministic and I/O-free; everything effectful sits
  behind `storage/` interfaces. This is what makes the verifier
  trustworthy and the internals replaceable.
- The verify exit-code contract (0/1/2) is public API from the first
  release.

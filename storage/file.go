package storage

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/itsalmirr/keystone/keylog"
)

// fileMagic identifies a keystone log file and pins its format version.
// Everything after the header may evolve behind this string (ADR-002).
const fileMagic = "keystone-log-v1\n"

// MaxRecordSize is the largest payload Append accepts and the largest
// length field recovery treats as legal (ADR-002).
const MaxRecordSize = 16 << 20 // 16 MiB

// CorruptError reports the first record that failed validation when
// opening or reading a log. Index is the record's zero-based index and
// Off the byte offset of its frame.
type CorruptError struct {
	Index  int64
	Off    int64
	Reason string
}

func (e *CorruptError) Error() string {
	return fmt.Sprintf("storage: corrupt record %d at offset %d: %s", e.Index, e.Off, e.Reason)
}

// FileStore is an AppendStore backed by a single append-only file laid
// out per ADR-002. It is safe for one writer and any number of
// concurrent readers. The caller that Opens a FileStore owns it and
// must Close it.
type FileStore struct {
	path string

	mu      sync.RWMutex
	f       *os.File
	offsets []int64   // offsets[i] = byte offset of record i's frame
	end     int64     // offset one past the last committed frame
	head    tlog.Hash // chain hash of the last record; zero when empty
	werr    error     // first write failure; fail-stop for appends
}

var _ AppendStore = (*FileStore)(nil)

// Open opens the log file at path, creating it if absent, and runs
// torn-write recovery: a forward scan that validates every frame and
// chain hash, truncating an incomplete final frame (ADR-002). It fails
// with a *CorruptError if any complete record is invalid.
func Open(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s := &FileStore{path: path, f: f}
	if err := s.recover(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *FileStore) recover() error {
	info, err := s.f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	hdrLen := int64(len(fileMagic))

	if size < hdrLen {
		// Empty file, or a creation torn mid-header.
		buf := make([]byte, size)
		if _, err := s.f.ReadAt(buf, 0); err != nil && size > 0 {
			return err
		}
		if !strings.HasPrefix(fileMagic, string(buf)) {
			return fmt.Errorf("storage: %s is not a keystone log", s.path)
		}
		if err := s.f.Truncate(0); err != nil {
			return err
		}
		if _, err := s.f.Write([]byte(fileMagic)); err != nil {
			return err
		}
		if err := s.f.Sync(); err != nil {
			return err
		}
		syncDir(s.path)
		s.end = hdrLen
		return nil
	}

	hdr := make([]byte, hdrLen)
	if _, err := s.f.ReadAt(hdr, 0); err != nil {
		return err
	}
	if string(hdr) != fileMagic {
		return fmt.Errorf("storage: %s is not a keystone log", s.path)
	}

	var (
		prev    tlog.Hash
		off     = hdrLen
		torn    = false
		payload []byte // reused across records; ChainHash does not retain it
		br      = bufio.NewReaderSize(io.NewSectionReader(s.f, hdrLen, size-hdrLen), 1<<16)
	)
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break // clean end
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				torn = true // length field cut short
				break
			}
			return err
		}
		plen := binary.BigEndian.Uint32(lenBuf[:])
		if plen > MaxRecordSize {
			return &CorruptError{
				Index:  int64(len(s.offsets)),
				Off:    off,
				Reason: fmt.Sprintf("length %d exceeds MaxRecordSize", plen),
			}
		}
		if off+frameLen(int64(plen)) > size {
			torn = true // payload or chain hash cut short
			break
		}
		if int(plen) > cap(payload) {
			payload = make([]byte, plen)
		}
		payload = payload[:plen]
		if _, err := io.ReadFull(br, payload); err != nil {
			return err
		}
		var stored tlog.Hash
		if _, err := io.ReadFull(br, stored[:]); err != nil {
			return err
		}
		if stored != keylog.ChainHash(prev, payload) {
			return &CorruptError{
				Index:  int64(len(s.offsets)),
				Off:    off,
				Reason: "chain hash mismatch",
			}
		}
		s.offsets = append(s.offsets, off)
		prev = stored
		off += frameLen(int64(plen))
	}
	if torn {
		if err := s.f.Truncate(off); err != nil {
			return err
		}
		if err := s.f.Sync(); err != nil {
			return err
		}
	}
	s.end = off
	s.head = prev
	return nil
}

// Append implements AppendStore. The record is durable — written and
// fsynced — before Append returns (ADR-002: the batch size is one).
func (s *FileStore) Append(ctx context.Context, data []byte) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) > MaxRecordSize {
		return 0, fmt.Errorf("storage: record of %d bytes exceeds MaxRecordSize (%d)", len(data), MaxRecordSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.werr != nil {
		return 0, fmt.Errorf("storage: store is stopped after earlier write failure: %w", s.werr)
	}

	next := keylog.ChainHash(s.head, data)
	frame := make([]byte, frameLen(int64(len(data))))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	copy(frame[4+len(data):], next[:])

	// One write, then fsync; a failure of either leaves at most an
	// unacknowledged partial frame, which the next Open truncates.
	if _, err := s.f.Write(frame); err != nil {
		s.werr = err
		return 0, err
	}
	if err := s.f.Sync(); err != nil {
		s.werr = err
		return 0, err
	}

	index := int64(len(s.offsets))
	s.offsets = append(s.offsets, s.end)
	s.end += int64(len(frame))
	s.head = next
	return index, nil
}

// ReadLeaf implements AppendStore, returning exactly the bytes that
// were committed at index. It trusts open-time validation and does not
// re-verify the chain (ADR-002).
func (s *FileStore) ReadLeaf(ctx context.Context, index int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	if index < 0 || index >= int64(len(s.offsets)) {
		s.mu.RUnlock()
		return nil, ErrOutOfRange
	}
	off := s.offsets[index]
	s.mu.RUnlock()

	var lenBuf [4]byte
	if _, err := s.f.ReadAt(lenBuf[:], off); err != nil {
		return nil, err
	}
	plen := binary.BigEndian.Uint32(lenBuf[:])
	if plen > MaxRecordSize {
		return nil, &CorruptError{Index: index, Off: off, Reason: fmt.Sprintf("length %d exceeds MaxRecordSize", plen)}
	}
	payload := make([]byte, plen)
	if _, err := s.f.ReadAt(payload, off+4); err != nil {
		return nil, err
	}
	return payload, nil
}

// Size implements AppendStore.
func (s *FileStore) Size(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.offsets)), nil
}

// Head returns the chain hash of the last committed record, or the zero
// hash for an empty log. This is the value a verifier retains out of
// band as its trust anchor (ADR-000).
func (s *FileStore) Head() tlog.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.head
}

// Close releases the underlying file. Appends are already durable, so
// Close performs no flushing.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

func frameLen(plen int64) int64 {
	return 4 + plen + tlog.HashSize
}

// syncDir fsyncs path's parent directory so a newly created log file
// survives a crash. Best-effort: some platforms reject directory fsync.
func syncDir(path string) {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

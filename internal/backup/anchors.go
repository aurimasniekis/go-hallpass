package backup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Anchor is one integrity-chain head exported for external append-only storage (PLAN §13.8, HP-CRY-008).
type Anchor struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash,omitempty"`
	At   string `json:"at,omitempty"`
}

func newAnchor(seq int64, hash []byte, atMicros int64) Anchor {
	return Anchor{Seq: seq, Hash: hex.EncodeToString(hash), At: time.UnixMicro(atMicros).UTC().Format(time.RFC3339Nano)}
}

// chainEntry is one integrity_chain row.
type chainEntry struct {
	seq                    int64
	segmentID              string
	manifest, prev, hashed []byte
	at                     int64
}

// walkChain visits integrity-chain entries in order, checking without the KEK that sequence numbers are contiguous
// from 1 and that each entry links to its predecessor with hash = SHA-256(prev_hash || manifest_sha256). It stops
// after upTo (0 = the whole chain) and returns the number of entries checked and the last one as an anchor.
func walkChain(ctx context.Context, d *sql.DB, upTo int64, visit func(chainEntry) error) (int64, Anchor, error) {
	const page = 1000
	prev := make([]byte, sha256.Size)
	var after, n int64
	var last Anchor
	for {
		entries, err := chainPage(ctx, d, after, page)
		if err != nil {
			return n, last, err
		}
		for _, e := range entries {
			if upTo > 0 && e.seq > upTo {
				return n, last, nil
			}
			if e.seq != after+1 {
				return n, last, fmt.Errorf("integrity chain gap: expected seq %d, found %d", after+1, e.seq)
			}
			if !bytes.Equal(e.prev, prev) {
				return n, last, fmt.Errorf("integrity chain link broken at seq %d", e.seq)
			}
			h := sha256.New()
			h.Write(prev)
			h.Write(e.manifest)
			if !bytes.Equal(h.Sum(nil), e.hashed) {
				return n, last, fmt.Errorf("integrity chain hash mismatch at seq %d", e.seq)
			}
			if visit != nil {
				if err := visit(e); err != nil {
					return n, last, err
				}
			}
			prev, after = e.hashed, e.seq
			last = newAnchor(e.seq, e.hashed, e.at)
			n++
		}
		if len(entries) < page {
			return n, last, nil
		}
	}
}

func checkChain(ctx context.Context, d *sql.DB, upTo int64) (int64, Anchor, error) {
	return walkChain(ctx, d, upTo, nil)
}

func chainPage(ctx context.Context, d *sql.DB, after int64, limit int) ([]chainEntry, error) {
	rows, err := d.QueryContext(ctx, "SELECT seq, segment_id, manifest_sha256, prev_hash, hash, at FROM integrity_chain WHERE seq > ? ORDER BY seq LIMIT ?", after, limit)
	if err != nil {
		return nil, fmt.Errorf("read integrity chain: %w", err)
	}
	defer rows.Close()
	var out []chainEntry
	for rows.Next() {
		var e chainEntry
		if err := rows.Scan(&e.seq, &e.segmentID, &e.manifest, &e.prev, &e.hashed, &e.at); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExportAnchors writes one JSON line {seq, hash, at} for every integrity-chain entry after since. The whole local
// chain is link-checked first, so a chain that is already inconsistent is never anchored. It returns the number of
// anchors written.
func ExportAnchors(ctx context.Context, d *sql.DB, since int64, w io.Writer) (int, error) {
	if since < 0 {
		return 0, errors.New("since must not be negative")
	}
	if _, _, err := checkChain(ctx, d, 0); err != nil {
		return 0, fmt.Errorf("refusing to export anchors: %w", err)
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n := 0
	after := since
	for {
		entries, err := chainPage(ctx, d, after, 1000)
		if err != nil {
			return n, err
		}
		for _, e := range entries {
			if err := enc.Encode(newAnchor(e.seq, e.hashed, e.at)); err != nil {
				return n, err
			}
			after = e.seq
			n++
		}
		if len(entries) < 1000 {
			return n, bw.Flush()
		}
	}
}

// AnchorReport is the outcome of VerifyAnchors.
type AnchorReport struct {
	Anchors       int      `json:"anchors"`
	Matched       int      `json:"matched"`
	LastAnchorSeq int64    `json:"last_anchor_seq"`
	LocalHeadSeq  int64    `json:"local_head_seq"`
	Problems      []string `json:"problems,omitempty"`
	OK            bool     `json:"ok"`
}

// VerifyAnchors compares previously exported anchors (JSON lines) with the local integrity chain. It detects history
// that was rewritten or removed up to the latest anchor: every anchored seq must exist locally with the same hash,
// the local chain must link correctly up to the latest anchor, and every chain entry up to it must still match the
// segment metadata it was computed from. Entries after the latest anchor are not protected (PLAN §13.8).
func VerifyAnchors(ctx context.Context, d *sql.DB, r io.Reader) (*AnchorReport, error) {
	anchors, err := readAnchors(r)
	if err != nil {
		return nil, err
	}
	rep := &AnchorReport{Anchors: len(anchors)}
	want := map[int64]string{}
	for _, a := range anchors {
		if prev, dup := want[a.Seq]; dup && prev != a.Hash {
			rep.Problems = append(rep.Problems, fmt.Sprintf("anchor file has two different hashes for seq %d", a.Seq))
		}
		want[a.Seq] = a.Hash
		rep.LastAnchorSeq = max(rep.LastAnchorSeq, a.Seq)
	}
	head, err := chainHead(ctx, d)
	if err != nil {
		return nil, err
	}
	rep.LocalHeadSeq = head.Seq
	local := map[int64]string{}
	_, _, err = walkChain(ctx, d, rep.LastAnchorSeq, func(e chainEntry) error {
		if _, ok := want[e.seq]; ok {
			local[e.seq] = hex.EncodeToString(e.hashed)
		}
		if p := checkEntryManifest(ctx, d, e); p != "" {
			rep.Problems = append(rep.Problems, p)
		}
		return nil
	})
	if err != nil {
		rep.Problems = append(rep.Problems, "local chain: "+err.Error())
	}
	for _, a := range anchors {
		got, ok := local[a.Seq]
		switch {
		case !ok:
			rep.Problems = append(rep.Problems, fmt.Sprintf("anchored seq %d is not in the local chain (history removed or truncated)", a.Seq))
		case got != a.Hash:
			rep.Problems = append(rep.Problems, fmt.Sprintf("seq %d: local hash %s differs from anchor %s (history rewritten)", a.Seq, got, a.Hash))
		default:
			rep.Matched++
		}
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

func readAnchors(r io.Reader) ([]Anchor, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var out []Anchor
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var a Anchor
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			return nil, fmt.Errorf("anchor line %d: %w", line, err)
		}
		if h, err := hex.DecodeString(a.Hash); a.Seq <= 0 || err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("anchor line %d: invalid seq or hash", line)
		}
		a.Hash = strings.ToLower(a.Hash)
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read anchors: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("no anchors in input")
	}
	return out, nil
}

// manifestDoc mirrors the canonical segment manifest that the recording service hashes into the integrity chain
// (internal/recording finalizeRowTx). Field order and types must stay identical; anchor tests with real recordings
// fail if they diverge.
type manifestDoc struct {
	SegmentID        string `json:"segment_id"`
	SessionID        string `json:"session_id"`
	ChannelID        string `json:"channel_id"`
	HeaderSHA256     string `json:"header_sha256"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	Frames           uint64 `json:"frames"`
	Bytes            int64  `json:"bytes"`
	Records          uint64 `json:"records"`
	FirstSeq         uint64 `json:"first_seq"`
	LastSeq          uint64 `json:"last_seq"`
	State            string `json:"state"`
}

// checkEntryManifest recomputes the manifest of the segment a chain entry refers to from its current row and
// reports when no plausible state reproduces manifest_sha256 (segment metadata changed after it was chained).
func checkEntryManifest(ctx context.Context, d *sql.DB, e chainEntry) string {
	var doc manifestDoc
	var header, ct []byte
	var frames, size, records, first, last sql.NullInt64
	err := d.QueryRowContext(ctx, `SELECT access_session_id, channel_id, header_sha256, ciphertext_sha256, frames, bytes, records, first_seq, last_seq, state
		FROM recording_segments WHERE id = ?`, e.segmentID).Scan(&doc.SessionID, &doc.ChannelID, &header, &ct, &frames, &size, &records, &first, &last, &doc.State)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Sprintf("seq %d: segment %s no longer exists", e.seq, e.segmentID)
	}
	if err != nil {
		return fmt.Sprintf("seq %d: read segment %s: %v", e.seq, e.segmentID, err)
	}
	doc.SegmentID = e.segmentID
	doc.HeaderSHA256, doc.CiphertextSHA256 = hex.EncodeToString(header), hex.EncodeToString(ct)
	doc.Frames, doc.Bytes, doc.Records = uint64(frames.Int64), size.Int64, uint64(records.Int64) //nolint:gosec // stored from uint64 counters
	doc.FirstSeq, doc.LastSeq = uint64(first.Int64), uint64(last.Int64)                          //nolint:gosec // stored from uint64 sequence numbers
	states := []string{doc.State}
	if doc.State == "deleted" { // retention keeps the row but changes its state after chaining
		states = []string{"finalized", "interrupted"}
	}
	for _, st := range states {
		doc.State = st
		b, err := json.Marshal(doc)
		if err != nil {
			return err.Error()
		}
		if s := sha256.Sum256(b); bytes.Equal(s[:], e.manifest) {
			return ""
		}
	}
	return fmt.Sprintf("seq %d: segment %s metadata no longer matches its chain entry", e.seq, e.segmentID)
}

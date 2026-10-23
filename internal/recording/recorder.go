// Package recording records SSH channel activity into encrypted HPREC1 segments and keeps their index and integrity
// chain in SQLite (PLAN §13, HP-REC-*, HP-CRY-004/005).
package recording

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Options configure the recording service.
type Options struct {
	Durability      string        // "group" (default) or "strict"
	FlushInterval   time.Duration // group-commit interval, ≤ 250ms
	SegmentMaxBytes int64
	SegmentMaxAge   time.Duration
	QueueRecords    int
	QueueBytes      int
	BlockTimeout    time.Duration
	Clock           clock.Clock
	Logger          *slog.Logger
	// Metrics records bytes/records written, queue depth, failures and segment finalize latency (HP-OBS-004).
	// Nil disables.
	Metrics *metrics.Metrics
}

// Service creates recorders and maintains the segment index.
type Service struct {
	s       *store.Store
	kr      *keyring.Keyring
	seq     *access.Sequencer
	opts    Options
	log     *slog.Logger
	dir     string
	qdir    string
	wrapper hprec.DEKWrapper
}

// New returns a recording service storing segments under <data>/recordings.
func New(s *store.Store, kr *keyring.Keyring, seq *access.Sequencer, o Options) *Service {
	if o.Durability == "" {
		o.Durability = "group"
	}
	if o.FlushInterval <= 0 || o.FlushInterval > 250*time.Millisecond {
		o.FlushInterval = 250 * time.Millisecond
	}
	if o.SegmentMaxBytes <= 0 {
		o.SegmentMaxBytes = 64 << 20
	}
	if o.SegmentMaxAge <= 0 {
		o.SegmentMaxAge = time.Hour
	}
	if o.QueueRecords <= 0 {
		o.QueueRecords = 1024
	}
	if o.QueueBytes <= 0 {
		o.QueueBytes = 1 << 20
	}
	if o.BlockTimeout <= 0 {
		o.BlockTimeout = 10 * time.Second
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{s: s, kr: kr, seq: seq, opts: o, log: obs.Component(o.Logger, "recording"),
		dir: s.Path(store.RecordingsDir), qdir: s.Path(store.QuarantineDir), wrapper: KeyringWrapper{KR: kr}}
}

// Wrapper returns the DEK wrapper used for segment keys.
func (svc *Service) Wrapper() hprec.DEKWrapper { return svc.wrapper }

// KeyringWrapper wraps segment DEKs with the keyring's recording key (ADR-0004).
type KeyringWrapper struct{ KR *keyring.Keyring }

// Wrap implements hprec.DEKWrapper.
func (k KeyringWrapper) Wrap(dek, aad []byte) (string, []byte, error) {
	sealed, err := k.KR.Seal(keyring.PurposeRecording, aad, dek)
	if err != nil {
		return "", nil, err
	}
	v, err := keyring.SealedVersion(sealed)
	if err != nil {
		return "", nil, err
	}
	return "recording:v" + strconv.FormatUint(uint64(v), 10), sealed, nil
}

// Unwrap implements hprec.DEKWrapper.
func (k KeyringWrapper) Unwrap(_ string, wrapped, aad []byte) ([]byte, error) {
	return k.KR.Open(keyring.PurposeRecording, aad, wrapped)
}

// segmentPath returns the final path for a segment (sharded by session).
func (svc *Service) segmentPath(sessionID, segmentID string) string {
	shard := "00"
	if len(sessionID) >= 2 {
		shard = sessionID[len(sessionID)-2:]
	}
	return filepath.Join(svc.dir, shard, sessionID, segmentID+".hprec")
}

// Open establishes a recording for a registered channel: the segment row is inserted, then the segment file with
// its header and key slots is created and fsynced. It returns only once the recording is established (HP-REC-007).
func (svc *Service) Open(ctx context.Context, reg *access.ChannelReg, kind string, pty bool) (sshproxy.Recorder, error) {
	k := hprec.KindExec
	if pty || kind == access.KindShell {
		k = hprec.KindPTY
	}
	r := &channelRecorder{
		svc: svc, reg: reg, kind: k, start: time.Now(), q: make(chan item, svc.opts.QueueRecords),
		bytes: make(chan struct{}, max(svc.opts.QueueBytes/1024, 1)), done: make(chan struct{}),
		strict: svc.opts.Durability == "strict", recordInput: reg.Role.RecordInput,
	}
	if err := r.openSegment(ctx, 0, nil); err != nil {
		return nil, err
	}
	go r.loop(context.WithoutCancel(ctx))
	return r, nil
}

type item struct {
	rec    hprec.Record
	tokens int
	ack    chan error // strict mode: signaled after the frame is fsynced
	final  string     // non-empty: finalize with this reason
	result chan error
}

type channelRecorder struct {
	svc         *Service
	reg         *access.ChannelReg
	kind        hprec.Kind
	start       time.Time
	q           chan item
	bytes       chan struct{} // 1 token per KiB queued
	done        chan struct{}
	strict      bool
	recordInput bool

	// owned by the loop goroutine
	w       *hprec.Writer
	segID   string
	ordinal uint32
	opened  time.Time

	// enqMu serializes sequence assignment with the hand-off to the writer so records reach the file in sequence
	// order even when stdout, stderr and stdin are recorded from different goroutines.
	enqMu sync.Mutex

	mu     sync.Mutex
	err    error
	closed bool
	once   sync.Once
}

func (r *channelRecorder) SegmentID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.segID
}

func (r *channelRecorder) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *channelRecorder) setErr(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
}

// openSegment registers the DB row first, then creates and fsyncs the file (PLAN §13.5 steps 1–2).
func (r *channelRecorder) openSegment(ctx context.Context, ordinal uint32, prev []byte) error {
	segID := ids.New(ids.Segment)
	var salt [hprec.SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	now := r.svc.opts.Clock.Now()
	prep, err := hprec.Prepare(hprec.Header{SegmentID: segID, SessionID: r.reg.SessionID, ChannelID: r.reg.ChannelID, Ordinal: ordinal,
		CreatedAt: now, Kind: r.kind, PrevSegmentSHA256: prev, PayloadSalt: salt}, r.svc.wrapper)
	if err != nil {
		return fmt.Errorf("prepare segment: %w", err)
	}
	path := r.svc.segmentPath(r.reg.SessionID, segID)
	hh := prep.HeaderSHA256()
	slot := prep.Slot()
	err = r.svc.s.W().TxNamed(ctx, "recording.open_segment", func(tx *store.Tx) error {
		return tx.Q.InsertSegment(ctx, db.InsertSegmentParams{ID: segID, AccessSessionID: r.reg.SessionID, ChannelID: r.reg.ChannelID,
			Ordinal: int64(ordinal), Path: path, KeyID: slot.KeyID, WrappedDek: slot.Wrapped, HeaderSha256: hh[:], OpenedAt: tx.NowMicros()})
	})
	if err != nil {
		prep.Discard()
		r.m().RecordingFailed(metrics.RecCreate)
		return fmt.Errorf("register segment: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		prep.Discard()
		r.markState(ctx, segID, "failed", "mkdir")
		r.m().RecordingFailed(metrics.RecCreate)
		r.m().SegmentClosed(metrics.SegmentFailed)
		return err
	}
	w, err := prep.Create(path)
	if err != nil {
		r.markState(ctx, segID, "failed", "create")
		r.m().RecordingFailed(metrics.RecCreate)
		r.m().SegmentClosed(metrics.SegmentFailed)
		return fmt.Errorf("create segment file: %w", err)
	}
	r.mu.Lock()
	r.w, r.segID, r.ordinal, r.opened = w, segID, ordinal, now
	r.mu.Unlock()
	return nil
}

func (r *channelRecorder) markState(ctx context.Context, segID, state, reason string) {
	_ = r.svc.s.W().TxNamed(context.WithoutCancel(ctx), "recording.mark", func(tx *store.Tx) error {
		_, err := tx.Q.SetSegmentState(ctx, db.SetSegmentStateParams{State: state, EndReason: sql.NullString{String: reason, Valid: true}, ID: segID, FromState: "open"})
		return err
	})
}

// enqueue assigns the session sequence number and hands the record to the writer, blocking (backpressure) up to
// BlockTimeout; it never drops records silently (HP-REC-011).
func (r *channelRecorder) enqueue(t hprec.RecordType, stream hprec.Stream, payload []byte) error {
	if err := r.failure(); err != nil {
		return err
	}
	if len(payload) > hprec.MaxRecordPayload {
		for len(payload) > 0 { // split oversized writes; order is preserved
			n := min(len(payload), hprec.MaxRecordPayload)
			if err := r.enqueue(t, stream, payload[:n]); err != nil {
				return err
			}
			payload = payload[n:]
		}
		return nil
	}
	r.enqMu.Lock()
	ack, err := r.enqueueLocked(t, stream, payload)
	r.enqMu.Unlock()
	if err != nil || ack == nil {
		return err
	}
	return <-ack
}

func (r *channelRecorder) enqueueLocked(t hprec.RecordType, stream hprec.Stream, payload []byte) (chan error, error) {
	if err := r.failure(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, hprec.ErrWriterClosed
	}
	seq, err := r.svc.seq.Next(context.Background(), r.reg.SessionID, 1)
	if err != nil {
		r.setErr(err)
		r.m().RecordingFailed(metrics.RecWrite)
		return nil, err
	}
	now := r.svc.opts.Clock.Now()
	it := item{rec: hprec.Record{Type: t, Seq: uint64(seq), Time: now, Mono: time.Since(r.start), Stream: stream, //nolint:gosec // seq ≥ 1
		Payload: append([]byte(nil), payload...)}, tokens: (len(payload) + 1023) / 1024}
	if r.strict {
		it.ack = make(chan error, 1)
	}
	deadline := time.NewTimer(r.svc.opts.BlockTimeout)
	defer deadline.Stop()
	for i := 0; i < it.tokens; i++ {
		select {
		case r.bytes <- struct{}{}:
		case <-deadline.C:
			err := errors.New("recording stalled: queue full beyond block timeout")
			r.setErr(err)
			r.m().RecordingFailed(metrics.RecQueueTimeout)
			return nil, err
		}
	}
	select {
	case r.q <- it:
	case <-deadline.C:
		err := errors.New("recording stalled: queue full beyond block timeout")
		r.setErr(err)
		r.m().RecordingFailed(metrics.RecQueueTimeout)
		return nil, err
	}
	r.m().RecordingQueueAdd(1)
	return it.ack, nil
}

// loop owns the writer: appends records, group-commits, rolls over, finalizes.
func (r *channelRecorder) loop(ctx context.Context) {
	defer close(r.done)
	tick := time.NewTicker(r.svc.opts.FlushInterval)
	defer tick.Stop()
	for {
		select {
		case it := <-r.q:
			if it.final != "" {
				it.result <- r.finalize(ctx, it.final)
				return
			}
			r.m().RecordingQueueAdd(-1)
			err := r.failure()
			if err == nil {
				err = r.write(ctx, it)
			}
			for range it.tokens {
				<-r.bytes
			}
			if it.ack != nil {
				it.ack <- err
			}
		case <-tick.C:
			if r.failure() == nil && r.w != nil && r.w.Pending() > 0 {
				if err := r.w.Flush(); err != nil {
					r.setErr(fmt.Errorf("recording flush: %w", err))
					r.m().RecordingFailed(metrics.RecFsync)
				}
			}
		}
	}
}

func (r *channelRecorder) write(ctx context.Context, it item) error {
	if r.w.Size()+int64(r.w.Pending()) >= r.svc.opts.SegmentMaxBytes || r.svc.opts.Clock.Now().Sub(r.opened) >= r.svc.opts.SegmentMaxAge {
		if err := r.rollover(ctx); err != nil {
			r.setErr(err)
			return err
		}
	}
	if err := r.w.Append(it.rec); err != nil {
		err = fmt.Errorf("recording append: %w", err)
		r.setErr(err)
		r.m().RecordingFailed(metrics.RecWrite)
		return err
	}
	if r.strict {
		if err := r.w.Flush(); err != nil {
			err = fmt.Errorf("recording fsync: %w", err)
			r.setErr(err)
			r.m().RecordingFailed(metrics.RecFsync)
			return err
		}
	}
	r.m().RecordingWritten(1, len(it.rec.Payload))
	return nil
}

func (r *channelRecorder) m() *metrics.Metrics { return r.svc.opts.Metrics }

func (r *channelRecorder) rollover(ctx context.Context) error {
	m, err := r.finishSegment(ctx, "rollover")
	if err != nil {
		return err
	}
	return r.openSegment(ctx, r.ordinal+1, m.CiphertextSHA256[:])
}

// finishSegment finalizes the current file and records the manifest and integrity-chain entry (PLAN §13.5 step 4).
func (r *channelRecorder) finishSegment(ctx context.Context, reason string) (hprec.Manifest, error) {
	start := time.Now()
	m, err := r.w.Finalize(reason)
	if err != nil {
		r.m().RecordingFailed(metrics.RecFinalize)
		r.m().SegmentClosed(metrics.SegmentFailed)
		return m, fmt.Errorf("recording finalize: %w", err)
	}
	err = r.svc.s.W().TxNamed(ctx, "recording.finalize", func(tx *store.Tx) error {
		return r.svc.finalizeRowTx(ctx, tx, r.segID, "finalized", m)
	})
	if err != nil {
		r.m().RecordingFailed(metrics.RecFinalize)
		r.m().SegmentClosed(metrics.SegmentFailed)
		return m, err
	}
	r.m().SegmentFinalized(time.Since(start))
	r.m().SegmentClosed(metrics.SegmentFinalized)
	return m, nil
}

func (r *channelRecorder) finalize(ctx context.Context, reason string) error {
	if r.w == nil {
		return nil
	}
	if err := r.failure(); err != nil {
		_ = r.w.Close()
		r.markState(ctx, r.segID, "failed", "write_error")
		r.m().SegmentClosed(metrics.SegmentFailed) // the failure itself was counted where it happened
		return err
	}
	_, err := r.finishSegment(ctx, reason)
	return err
}

// stop sends the final item and waits for the loop.
func (r *channelRecorder) stop(reason string) error {
	var err error
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		res := make(chan error, 1)
		r.q <- item{final: reason, result: res}
		err = <-res
		<-r.done
	})
	return err
}

// Finalize implements sshproxy.Recorder.
func (r *channelRecorder) Finalize(reason string) error { return r.stop(reason) }

// Abort implements sshproxy.Recorder: the segment is marked failed; the file keeps its authentic prefix.
func (r *channelRecorder) Abort(err error) {
	r.setErr(err)
	_ = r.stop("failed")
}

func (r *channelRecorder) ExecRequested(cmd string) error {
	return r.enqueue(hprec.RecExecRequested, hprec.StreamMeta, []byte(cmd))
}

func (r *channelRecorder) PTY(p *sshproxy.PTYRequest) error {
	return r.enqueue(hprec.RecPTYRequested, hprec.StreamMeta, hprec.PTYRequest{Term: p.Term, Cols: p.Cols, Rows: p.Rows,
		WidthPx: p.Width, HeightPx: p.Height}.Marshal())
}

func (r *channelRecorder) Resize(cols, rows uint32) error {
	return r.enqueue(hprec.RecTerminalResized, hprec.StreamMeta, hprec.Resize{Cols: cols, Rows: rows}.Marshal())
}

func (r *channelRecorder) Output(s sshproxy.Stream, data []byte) error {
	switch s {
	case sshproxy.StreamStdout:
		return r.enqueue(hprec.RecStdout, hprec.StreamStdout, data)
	case sshproxy.StreamStderr:
		return r.enqueue(hprec.RecStderr, hprec.StreamStderr, data)
	default:
		return r.enqueue(hprec.RecTerminalOutput, hprec.StreamPTY, data)
	}
}

func (r *channelRecorder) Input(data []byte) error {
	if !r.recordInput {
		return nil
	}
	return r.enqueue(hprec.RecTerminalInput, hprec.StreamStdin, data)
}

func (r *channelRecorder) Signal(sig string) error {
	return r.enqueue(hprec.RecSignal, hprec.StreamMeta, hprec.Signal{Name: sig}.Marshal())
}

func (r *channelRecorder) EOF(s sshproxy.Stream) error {
	return r.enqueue(hprec.RecEOF, hprec.Stream(s), nil)
}

func (r *channelRecorder) Exit(status *int, signal string) error {
	e := hprec.Exit{Signal: signal}
	if status != nil {
		e.Status = uint32(*status) //nolint:gosec // exit codes 0..255
	}
	return r.enqueue(hprec.RecExit, hprec.StreamMeta, e.Marshal())
}

func (r *channelRecorder) Notice(text string) error {
	return r.enqueue(hprec.RecGatewayNotice, hprec.StreamMeta, hprec.Notice{Code: "gateway", Message: text}.Marshal())
}

// manifestDoc is the canonical manifest hashed into the integrity chain.
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

// finalizeRowTx records a segment's manifest and appends it to the integrity chain:
// hash = SHA-256(prev_hash || manifest_sha256), mac = HMAC(manifest key, hash) (PLAN §13.5, HP-CRY-005).
func (svc *Service) finalizeRowTx(ctx context.Context, tx *store.Tx, segID, state string, m hprec.Manifest) error {
	row, err := tx.Q.GetSegment(ctx, segID)
	if err != nil {
		return err
	}
	n, err := tx.Q.FinalizeSegment(ctx, db.FinalizeSegmentParams{State: state, FirstSeq: nullI(int64(m.FirstSeq)), LastSeq: nullI(int64(m.LastSeq)), //nolint:gosec // sequence numbers fit int64
		Records: nullI(int64(m.Records)), Frames: nullI(int64(m.Frames)), Bytes: nullI(m.Bytes), CiphertextSha256: m.CiphertextSHA256[:], //nolint:gosec // counts fit int64
		EndReason: sql.NullString{String: m.EndReason, Valid: m.EndReason != ""}, Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, ID: segID})
	if err != nil || n == 0 {
		return err
	}
	doc, _ := json.Marshal(manifestDoc{SegmentID: segID, SessionID: row.AccessSessionID, ChannelID: row.ChannelID,
		HeaderSHA256: hex.EncodeToString(m.HeaderSHA256[:]), CiphertextSHA256: hex.EncodeToString(m.CiphertextSHA256[:]), Frames: m.Frames,
		Bytes: m.Bytes, Records: m.Records, FirstSeq: m.FirstSeq, LastSeq: m.LastSeq, State: state})
	return svc.appendChainTx(ctx, tx, segID, doc)
}

func (svc *Service) appendChainTx(ctx context.Context, tx *store.Tx, segID string, manifest []byte) error {
	ms := sha256.Sum256(manifest)
	seq, prev := int64(1), make([]byte, sha256.Size)
	head, err := tx.Q.ChainHead(ctx)
	switch {
	case err == nil:
		seq, prev = head.Seq+1, head.Hash
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(ms[:])
	hash := h.Sum(nil)
	mac, err := svc.kr.MAC(keyring.PurposeManifest, hash)
	if err != nil {
		return err
	}
	return tx.Q.InsertChainEntry(ctx, db.InsertChainEntryParams{Seq: seq, SegmentID: segID, ManifestSha256: ms[:], PrevHash: prev, Hash: hash, Mac: mac, At: tx.NowMicros()})
}

func nullI(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

// Shipper signs and posts batches to Hallpass.
type Shipper struct {
	// URL is the full ingestion URL, e.g. https://hallpass.example.com/hooks/destaudit/dac_….
	URL         string
	CollectorID string
	Key         ed25519.PrivateKey
	Client      *http.Client
	// StatePath, if set, persists the last accepted sequence number (0600, atomic replace).
	StatePath string
	// Retries for network errors and 5xx responses (the same signed envelope is resent; Hallpass recognizes an exact
	// resend of an accepted batch). Default 3.
	Retries int
	Now     func() time.Time
	// Sleep waits between retries (overridable in tests).
	Sleep func(context.Context, time.Duration) error

	lastSeq int64
}

// PermanentError is a rejection that retrying the same batch cannot fix (bad signature, malformed batch, revoked
// collector).
type PermanentError struct {
	Status int
	Body   string
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("hallpass rejected the batch: HTTP %d: %s", e.Status, e.Body)
}

// LoadState reads the persisted sequence number, if any.
func (s *Shipper) LoadState() error {
	if s.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid state file %s", s.StatePath)
	}
	s.lastSeq = n
	return nil
}

func (s *Shipper) saveState() error {
	if s.StatePath == "" {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.StatePath), ".hallpass-collector-state-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(strconv.FormatInt(s.lastSeq, 10) + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.StatePath)
}

// nextSeq is strictly greater than every sequence used before and at least the current time in microseconds, so a
// collector that lost its state file still moves forward (as long as its clock does).
func (s *Shipper) nextSeq() int64 {
	return max(s.lastSeq+1, s.now().UnixMicro())
}

func (s *Shipper) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Result aggregates Hallpass's answers for one Send.
type Result struct {
	Batches  int
	Accepted int
	Rejected int
	// Rejections are per-record reasons reported by Hallpass (e.g. no_session, ambiguous).
	Rejections []RecordRejection
}

// RecordRejection is one record Hallpass did not attach.
type RecordRejection struct {
	RecordID string `json:"record_id"`
	Reason   string `json:"reason"`
}

type ingestResult struct {
	Accepted   int               `json:"accepted"`
	Rejected   int               `json:"rejected"`
	Rejections []RecordRejection `json:"rejections"`
}

// Send ships records in as many batches as the limits require.
func (s *Shipper) Send(ctx context.Context, recs []wire.Record) (*Result, error) {
	res := &Result{}
	for len(recs) > 0 {
		n := min(len(recs), wire.MaxRecords)
		for {
			env, size, err := s.sign(recs[:n])
			if err != nil {
				return res, err
			}
			if size > wire.MaxEnvelopeBytes && n > 1 {
				n /= 2
				continue
			}
			if size > wire.MaxEnvelopeBytes {
				return res, fmt.Errorf("record %s does not fit in a batch", recs[0].ID)
			}
			r, err := s.post(ctx, env, recs[:n])
			if err != nil {
				return res, err
			}
			res.Batches++
			res.Accepted += r.Accepted
			res.Rejected += r.Rejected
			res.Rejections = append(res.Rejections, r.Rejections...)
			break
		}
		recs = recs[n:]
	}
	return res, nil
}

func (s *Shipper) sign(recs []wire.Record) (*wire.Envelope, int, error) {
	b := &wire.Batch{V: wire.Version, CollectorID: s.CollectorID, Seq: s.nextSeq(), SentAt: s.now().UTC(), Records: recs}
	env, err := wire.Sign(s.Key, b)
	if err != nil {
		return nil, 0, err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, 0, err
	}
	return env, len(raw), nil
}

func (s *Shipper) post(ctx context.Context, env *wire.Envelope, recs []wire.Record) (*ingestResult, error) {
	retries := s.Retries
	if retries <= 0 {
		retries = 3
	}
	resynced := false
	for attempt := 0; ; attempt++ {
		status, body, err := s.do(ctx, env)
		switch {
		case err == nil && status == http.StatusOK:
			var r ingestResult
			if err := json.Unmarshal(body, &r); err != nil {
				return nil, fmt.Errorf("unexpected response: %w", err)
			}
			var b wire.Batch
			if err := json.Unmarshal(env.Payload, &b); err != nil {
				return nil, err
			}
			s.lastSeq = b.Seq
			return &r, s.saveState()
		case err == nil && status == http.StatusConflict && !resynced:
			// Replay refusal: our sequence is behind Hallpass (lost state, clock behind). Resign above last_seq once.
			var p struct {
				LastSeq *int64 `json:"last_seq"`
			}
			if json.Unmarshal(body, &p) != nil || p.LastSeq == nil {
				return nil, &PermanentError{Status: status, Body: snippet(body)}
			}
			s.lastSeq = max(s.lastSeq, *p.LastSeq)
			resynced = true
			if env, _, err = s.sign(recs); err != nil {
				return nil, err
			}
			continue
		case err == nil && status < 500 && status != http.StatusTooManyRequests:
			return nil, &PermanentError{Status: status, Body: snippet(body)}
		}
		if attempt >= retries {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("hallpass unavailable: HTTP %d: %s", status, snippet(body))
		}
		if err := s.sleep(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
			return nil, err
		}
	}
}

func (s *Shipper) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *Shipper) do(ctx context.Context, env *wire.Envelope) (int, []byte, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hallpass-collector/1")
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

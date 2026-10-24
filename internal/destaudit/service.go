// Package destaudit ingests optional destination-side exec audit records from signed collectors and attaches them to
// access-session timelines (WP25, HP-REC-012).
//
// Trust model: a collector runs on a destination host, which HallPass treats as untrusted (THREAT_MODEL AD-4). The
// collector signs each batch with its own Ed25519 key, so HallPass can verify that a batch came from the enrolled
// collector, was not modified in transit and is not a replay. It cannot verify that the destination reported the
// truth: a root user on the destination can forge, suppress or alter audit records. Every ingested record is therefore
// labeled provenance "destination-audit", verified=false, with a correlation method and confidence, and never
// upgrades any HallPass-captured fact (HP-REC-006 spirit).
//
// Correlation never trusts a collector-supplied session identifier. The collector reports only what sshd and the
// kernel logged (the certificate key ID or login key fingerprint, the account and times); HallPass checks those
// claims against its own server, role, grant, connection and time-window state and refuses anything ambiguous.
package destaudit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// ID prefixes.
const (
	PrefixCollector = "dac"
	PrefixRecord    = "dar"
)

// Provenance and correlation labels written into destination.exec timeline events.
const (
	Provenance = "destination-audit"

	CorrelationCertKeyID   = "certificate_key_id"    // sshd logged a HallPass certificate key ID naming grant + connection
	CorrelationKeyWindow   = "login_key_time_window" // managed login key fingerprint + exactly one session in the time window
	CorrelationLoginBinded = "login_binding"         // same destination login as an earlier correlated record

	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
)

// Collector states.
const (
	StateActive  = "active"
	StateRevoked = "revoked"
)

// Options configure the service.
type Options struct {
	// MaxSkew bounds the difference between a batch's sent_at and HallPass's clock, and the slack applied to
	// session time windows during correlation. Default 2m.
	MaxSkew time.Duration
	// MaxRecordAge rejects records older than this (relative to now). Default 24h.
	MaxRecordAge time.Duration
	// PostSessionWindow accepts records up to this long after the access session ended (flagged
	// after_session_end: detached processes, HP-SES-004). Default 24h.
	PostSessionWindow time.Duration
	// MaxBodyBytes limits the HTTP body. Default wire.MaxEnvelopeBytes.
	MaxBodyBytes int64
	Clock        clock.Clock
	Logger       *slog.Logger
	// Bus, if set, receives session.updated after records are attached.
	Bus *eventbus.Bus
}

// Service manages collectors and ingests their batches.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	seq   *access.Sequencer
	opts  Options
	log   *slog.Logger

	locks sync.Map // collector ID → *sync.Mutex (serializes ingestion per collector)
}

// New returns a service. seq must be the access service's sequencer (access.Service.Sequencer()).
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, seq *access.Sequencer, o Options) *Service {
	if o.MaxSkew <= 0 {
		o.MaxSkew = 2 * time.Minute
	}
	if o.MaxRecordAge <= 0 {
		o.MaxRecordAge = 24 * time.Hour
	}
	if o.PostSessionWindow <= 0 {
		o.PostSessionWindow = 24 * time.Hour
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = wire.MaxEnvelopeBytes
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{s: s, kr: kr, audit: aw, seq: seq, opts: o, log: obs.Component(o.Logger, "destaudit")}
}

// Collector is an enrolled destination collector. The private key never leaves the destination.
type Collector struct {
	ID           string     `json:"id"`
	ServerID     string     `json:"server_id"`
	Name         string     `json:"name"`
	PublicKey    string     `json:"public_key"` // authorized_keys format ("ssh-ed25519 AAAA…")
	Fingerprint  string     `json:"fingerprint"`
	State        string     `json:"state"`
	LastSeq      int64      `json:"last_seq"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
}

// RegisterInput enrolls a collector for one server.
type RegisterInput struct {
	ServerID string
	Name     string
	// PublicKey is the collector's Ed25519 public key in authorized_keys format, as printed by
	// `hallpass-collector keygen`.
	PublicKey string
}

// ParsePublicKey accepts an authorized_keys-format ssh-ed25519 key and returns the raw key and its fingerprint.
func ParsePublicKey(s string) (ed25519.PublicKey, string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(s)))
	if err != nil {
		return nil, "", invalid("public_key", "must be an ssh-ed25519 public key in authorized_keys format")
	}
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, "", invalid("public_key", "must be an ssh-ed25519 key")
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, "", invalid("public_key", "unsupported key")
	}
	raw, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok || len(raw) != ed25519.PublicKeySize {
		return nil, "", invalid("public_key", "unsupported key")
	}
	return raw, ssh.FingerprintSHA256(pk), nil
}

func invalid(field, msg string) error {
	var v apperr.Validation
	v.Add(field, "%s", msg)
	return v.Err()
}

func validName(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// RegisterCollector enrolls a collector. Callers must enforce an admin permission and recent authentication: a
// collector can attach destination-reported records to every session on its server.
func (svc *Service) RegisterCollector(ctx context.Context, actor audit.Actor, in RegisterInput) (*Collector, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !validName(in.Name) {
		return nil, invalid("name", "must be 1–64 printable characters")
	}
	raw, fp, err := ParsePublicKey(in.PublicKey)
	if err != nil {
		return nil, err
	}
	id := ids.New(PrefixCollector)
	err = svc.s.W().TxNamed(ctx, "destaudit.register", func(tx *store.Tx) error {
		if _, err := tx.Q.GetServer(ctx, in.ServerID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		if err := tx.Q.InsertDestauditCollector(ctx, db.InsertDestauditCollectorParams{ID: id, ServerID: in.ServerID, Name: in.Name,
			PublicKey: raw, Fingerprint: fp, CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor)}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "a collector with this name or public key already exists")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "destaudit.collector.registered",
			Target:  audit.Target{Type: "destaudit_collector", ID: id},
			Details: map[string]any{"server_id": in.ServerID, "name": in.Name, "fingerprint": fp}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetCollector(ctx, id)
}

// RevokeCollector stops accepting batches from a collector. Records already attached stay, labeled as before.
func (svc *Service) RevokeCollector(ctx context.Context, actor audit.Actor, id, reason string) (*Collector, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 512 {
		return nil, invalid("reason", "must be at most 512 bytes")
	}
	err := svc.s.W().TxNamed(ctx, "destaudit.revoke", func(tx *store.Tx) error {
		n, err := tx.Q.RevokeDestauditCollector(ctx, db.RevokeDestauditCollectorParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokedBy: sql.NullString{String: actorRef(actor), Valid: true}, Reason: sql.NullString{String: reason, Valid: reason != ""}, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Q.GetDestauditCollector(ctx, id); errors.Is(err, sql.ErrNoRows) {
				return apperr.New(apperr.CodeNotFound, "collector not found")
			} else if err != nil {
				return err
			}
			return apperr.New(apperr.CodeConflict, "collector is already revoked")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "destaudit.collector.revoked",
			Target: audit.Target{Type: "destaudit_collector", ID: id}, Sensitive: sensitiveReason(reason)})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetCollector(ctx, id)
}

func sensitiveReason(reason string) map[string]any {
	if reason == "" {
		return nil
	}
	return map[string]any{"reason": reason}
}

// GetCollector returns one collector.
func (svc *Service) GetCollector(ctx context.Context, id string) (*Collector, error) {
	r, err := svc.s.R().GetDestauditCollector(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "collector not found")
	}
	if err != nil {
		return nil, err
	}
	return collectorFromRow(r), nil
}

// ListCollectors lists collectors, optionally for one server ("" lists all).
func (svc *Service) ListCollectors(ctx context.Context, serverID string) ([]*Collector, error) {
	var filter any
	if serverID != "" {
		filter = serverID
	}
	rows, err := svc.s.R().ListDestauditCollectors(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*Collector, 0, len(rows))
	for _, r := range rows {
		out = append(out, collectorFromRow(r))
	}
	return out, nil
}

func collectorFromRow(r db.DestauditCollector) *Collector {
	c := &Collector{ID: r.ID, ServerID: r.ServerID, Name: r.Name, Fingerprint: r.Fingerprint, State: r.State, LastSeq: r.LastSeq,
		CreatedAt: clock.FromMicros(r.CreatedAt), CreatedBy: r.CreatedBy, RevokedBy: r.RevokedBy.String, RevokeReason: r.RevokeReason.String}
	if pk, err := ssh.NewPublicKey(ed25519.PublicKey(r.PublicKey)); err == nil {
		c.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	}
	if r.LastSeenAt.Valid {
		t := clock.FromMicros(r.LastSeenAt.Int64)
		c.LastSeenAt = &t
	}
	if r.RevokedAt.Valid {
		t := clock.FromMicros(r.RevokedAt.Int64)
		c.RevokedAt = &t
	}
	return c
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}

func (svc *Service) lock(collectorID string) func() {
	m, _ := svc.locks.LoadOrStore(collectorID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

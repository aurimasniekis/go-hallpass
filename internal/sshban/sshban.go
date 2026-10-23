// Package sshban bans SSH sources after repeated failed authentication, fail2ban style (HP-SSH-026). A source is an
// IPv4 address or an IPv6 /64 (one host usually controls a whole /64). Only failed authentication attempts count,
// never plain TCP connects, so load-balancer health checks are not banned. Banned sources are refused right after
// accept, before any SSH processing. Bans persist in SQLite, survive restarts, are audited, and can be lifted by an
// administrator. Each further ban of a source within 7 days doubles its duration up to the configured maximum.
package sshban

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// maxTracked bounds the failure table: a flood of distinct sources cannot grow memory without bound.
const maxTracked = 65536

// offenseWindow is how far back earlier bans of a source count toward its next ban's duration.
const offenseWindow = 7 * 24 * time.Hour

// Ban is an active ban.
type Ban struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Failures  int       `json:"failures"`
	Reason    string    `json:"reason"`
	Offense   int       `json:"offense"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Service tracks failures and bans.
type Service struct {
	s     *store.Store
	audit *audit.Writer
	clk   clock.Clock
	cfg   config.SSHBanConfig
	allow []netip.Prefix
	log   *slog.Logger

	mu       sync.Mutex
	failures map[string][]time.Time // source → failure times inside the window
	bans     map[string]Ban         // source → active ban
}

// New loads the active bans from the store.
func New(ctx context.Context, s *store.Store, aw *audit.Writer, clk clock.Clock, cfg config.SSHBanConfig, log *slog.Logger) (*Service, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	svc := &Service{s: s, audit: aw, clk: clk, cfg: cfg, log: obs.Component(log, "sshban"), failures: map[string][]time.Time{}, bans: map[string]Ban{}}
	for _, c := range cfg.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ssh.ban.allow_cidrs: %w", err)
		}
		svc.allow = append(svc.allow, p.Masked())
	}
	rows, err := s.R().ActiveSSHBans(ctx, clk.Now().UnixMicro())
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		svc.bans[r.Address] = fromRow(r)
	}
	return svc, nil
}

func fromRow(r db.SshBan) Ban {
	return Ban{ID: r.ID, Address: r.Address, Failures: int(r.Failures), Reason: r.Reason, Offense: int(r.Offense),
		BannedAt: clock.FromMicros(r.BannedAt), ExpiresAt: clock.FromMicros(r.ExpiresAt)}
}

// Source returns the ban key of an address: the IPv4 address, or the IPv6 /64.
func Source(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (svc *Service) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range svc.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Banned reports whether connections from ip must be refused now.
func (svc *Service) Banned(ip netip.Addr) bool {
	if svc == nil || !svc.cfg.Enabled {
		return false
	}
	key := Source(ip)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	b, ok := svc.bans[key]
	if !ok {
		return false
	}
	if !svc.clk.Now().Before(b.ExpiresAt) {
		delete(svc.bans, key)
		return false
	}
	return true
}

// Failed records a failed authentication from ip and bans the source when it reaches the threshold. It writes to
// the store only when a ban is created; it must not be called inside a transaction.
func (svc *Service) Failed(ctx context.Context, ip netip.Addr, reason string) {
	if svc == nil || !svc.cfg.Enabled || !ip.IsValid() || svc.allowed(ip) {
		return
	}
	key, now := Source(ip), svc.clk.Now()
	svc.mu.Lock()
	if _, banned := svc.bans[key]; banned {
		svc.mu.Unlock()
		return
	}
	cut := now.Add(-svc.cfg.Window.D())
	times := svc.failures[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) < svc.cfg.MaxFailures {
		if _, tracked := svc.failures[key]; !tracked && len(svc.failures) >= maxTracked {
			svc.pruneLocked(cut)
		}
		if len(svc.failures) < maxTracked {
			svc.failures[key] = kept
		}
		svc.mu.Unlock()
		return
	}
	delete(svc.failures, key)
	svc.mu.Unlock()
	if err := svc.ban(ctx, key, len(kept), reason); err != nil {
		svc.log.Error("could not record SSH ban", slog.String("source", key), obs.Err(err))
	}
}

func (svc *Service) pruneLocked(cut time.Time) {
	for k, times := range svc.failures {
		if len(times) == 0 || !times[len(times)-1].After(cut) {
			delete(svc.failures, k)
		}
	}
}

func (svc *Service) ban(ctx context.Context, key string, failures int, reason string) error {
	ctx = context.WithoutCancel(ctx)
	var b Ban
	err := svc.s.W().TxNamed(ctx, "sshban.ban", func(tx *store.Tx) error {
		prior, err := tx.Q.CountSSHBansSince(ctx, db.CountSSHBansSinceParams{Address: key, Since: tx.Now.Add(-offenseWindow).UnixMicro()})
		if err != nil {
			return err
		}
		offense := int(prior) + 1
		d := svc.cfg.Duration.D()
		for i := 1; i < offense && d < svc.cfg.MaxDuration.D(); i++ {
			d *= 2
		}
		d = min(d, svc.cfg.MaxDuration.D())
		b = Ban{ID: ids.New(ids.SSHBan), Address: key, Failures: failures, Reason: reason, Offense: offense, BannedAt: tx.Now, ExpiresAt: tx.Now.Add(d)}
		if err := tx.Q.InsertSSHBan(ctx, db.InsertSSHBanParams{ID: b.ID, Address: key, Failures: int64(failures), Reason: reason, Offense: int64(offense),
			BannedAt: b.BannedAt.UnixMicro(), ExpiresAt: b.ExpiresAt.UnixMicro()}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "ssh.source.banned", Outcome: audit.OutcomeDenied,
			Target: audit.Target{Type: "ssh_ban", ID: b.ID}, SourceIP: key,
			Details: map[string]any{"failures": failures, "reason": reason, "offense": offense, "expires_at": b.ExpiresAt}})
		return err
	})
	if err != nil {
		return err
	}
	svc.mu.Lock()
	svc.bans[key] = b
	svc.mu.Unlock()
	svc.log.Warn("SSH source banned after repeated failed authentication", slog.String("source", key), slog.Int("failures", failures),
		slog.Int("offense", b.Offense), slog.Time("expires_at", b.ExpiresAt))
	return nil
}

// List returns the active bans, newest first.
func (svc *Service) List(ctx context.Context) ([]Ban, error) {
	rows, err := svc.s.R().ActiveSSHBans(ctx, svc.clk.Now().UnixMicro())
	if err != nil {
		return nil, err
	}
	out := make([]Ban, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	return out, nil
}

// Lift ends a ban early (audited). The source's offense history is kept.
func (svc *Service) Lift(ctx context.Context, actor audit.Actor, id string) error {
	var addr string
	err := svc.s.W().TxNamed(ctx, "sshban.lift", func(tx *store.Tx) error {
		r, err := tx.Q.GetSSHBan(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "ban not found")
		}
		if err != nil {
			return err
		}
		n, err := tx.Q.LiftSSHBan(ctx, db.LiftSSHBanParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			LiftedBy: sql.NullString{String: actor.Type + ":" + actor.ID, Valid: true}, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "ban is not active")
		}
		addr = r.Address
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "ssh.source.unbanned", Target: audit.Target{Type: "ssh_ban", ID: id},
			Details: map[string]any{"address": r.Address}})
		return err
	})
	if err != nil {
		return err
	}
	svc.mu.Lock()
	delete(svc.bans, addr)
	delete(svc.failures, addr)
	svc.mu.Unlock()
	return nil
}

// Purge deletes ban rows that expired more than 30 days ago (background job).
func (svc *Service) Purge(ctx context.Context) error {
	return svc.s.W().TxNamed(ctx, "sshban.purge", func(tx *store.Tx) error {
		return tx.Q.PurgeSSHBans(ctx, tx.Now.Add(-30*24*time.Hour).UnixMicro())
	})
}

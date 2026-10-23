package access

import (
	"context"
	"database/sql"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// ReconcileResult summarizes startup reconciliation.
type ReconcileResult struct {
	Connections      int64
	Channels         int
	RequestsExpired  int
	GrantsExpired    int
	PolicyCanceled   int
	PolicyRevoked    int
	SessionsClosed   int
	SessionsAffected []string
}

// ReconcileStartup repairs state left by a crash or restart (HP-DB-013): connections and channels from earlier boots
// become interrupted (with timeline events), due requests and grants expire, policy is re-applied and finished
// sessions close. Recording segments are reconciled separately by the recorder (WP12).
func (svc *Service) ReconcileStartup(ctx context.Context) (*ReconcileResult, error) {
	res := &ReconcileResult{}
	var interrupted []db.InterruptStaleChannelsRow
	err := svc.s.W().TxNamed(ctx, "access.reconcile_startup", func(tx *store.Tx) error {
		var err error
		if res.Connections, err = tx.Q.InterruptStaleConnections(ctx, db.InterruptStaleConnectionsParams{
			ClosedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, BootID: svc.opts.BootID}); err != nil {
			return err
		}
		interrupted, err = tx.Q.InterruptStaleChannels(ctx, db.InterruptStaleChannelsParams{
			ClosedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, BootID: svc.opts.BootID})
		return err
	})
	if err != nil {
		return nil, err
	}
	res.Channels = len(interrupted)
	for _, ch := range interrupted {
		seq, err := svc.seq.Next(ctx, ch.AccessSessionID, 1)
		if err != nil {
			return nil, err
		}
		if err := svc.s.W().TxNamed(ctx, "access.reconcile_event", func(tx *store.Tx) error {
			return appendTimeline(ctx, tx, TimelineEvent{SessionID: ch.AccessSessionID, Seq: seq, Type: EvChannelExited, ChannelID: ch.ID,
				ConnectionID: ch.ConnectionID, Data: map[string]any{"reason": "process_restart", "interrupted": true},
				IdempotencyKey: "reconcile|" + ch.ID})
		}); err != nil {
			return nil, err
		}
		res.SessionsAffected = append(res.SessionsAffected, ch.AccessSessionID)
	}
	if res.RequestsExpired, res.GrantsExpired, err = svc.ExpireDue(ctx); err != nil {
		return nil, err
	}
	if res.PolicyCanceled, res.PolicyRevoked, _, err = svc.ReconcilePolicy(ctx); err != nil {
		return nil, err
	}
	if res.SessionsClosed, err = svc.CloseFinishedSessions(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// RunBackground runs expiry sweeps (every sweep interval) and policy reconciliation (on policy.changed events and
// every minute) until ctx is canceled.
func (svc *Service) RunBackground(ctx context.Context, sweep time.Duration) {
	if sweep <= 0 {
		sweep = time.Second
	}
	var policyEvents <-chan eventbus.Event
	if svc.bus != nil {
		sub := svc.bus.Subscribe(64, eventbus.TopicPolicyChanged)
		defer sub.Close()
		policyEvents = sub.C
	}
	sweepT := time.NewTicker(sweep)
	defer sweepT.Stop()
	policyT := time.NewTicker(time.Minute)
	defer policyT.Stop()
	reconcile := func() {
		if c, r, cl, err := svc.ReconcilePolicy(ctx); err != nil && ctx.Err() == nil {
			svc.log.Warn("policy reconciliation failed", obs.Err(err))
		} else if c+r+cl > 0 {
			svc.log.Info("policy change applied", "canceled_requests", c, "revoked_grants", r, "clamped_grants", cl)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepT.C:
			if _, _, err := svc.ExpireDue(ctx); err != nil && ctx.Err() == nil {
				svc.log.Warn("expiry sweep failed", obs.Err(err))
			}
		case <-policyEvents:
			reconcile()
		case <-policyT.C:
			reconcile()
		}
	}
}

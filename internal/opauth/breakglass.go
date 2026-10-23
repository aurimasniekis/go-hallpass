package opauth

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// settingBreakGlassAck stores the audit sequence of the last acknowledged break-glass use.
const settingBreakGlassAck = "auth.breakglass_ack_seq"

// BreakGlassAlert reports an unacknowledged break-glass use (`hallpass admin recover`): it is raised at every start
// and in the system status until an administrator acknowledges it (HP-AUTH-016, PLAN §18.16).
func (svc *Service) BreakGlassAlert(ctx context.Context) (bool, time.Time, error) {
	rows, err := svc.s.R().ListAuditPage(ctx, db.ListAuditPageParams{Action: sql.NullString{String: "breakglass.used", Valid: true}, Lim: 1})
	if err != nil || len(rows) == 0 {
		return false, time.Time{}, err
	}
	ack := int64(0)
	if v, err := svc.s.R().GetSetting(ctx, settingBreakGlassAck); err == nil {
		ack, _ = strconv.ParseInt(v.Value, 10, 64)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, time.Time{}, err
	}
	if rows[0].Seq <= ack {
		return false, time.Time{}, nil
	}
	return true, time.UnixMicro(rows[0].At).UTC(), nil
}

// AcknowledgeBreakGlass clears the alert for every break-glass use recorded so far (audited).
func (svc *Service) AcknowledgeBreakGlass(ctx context.Context, actor audit.Actor) error {
	rows, err := svc.s.R().ListAuditPage(ctx, db.ListAuditPageParams{Action: sql.NullString{String: "breakglass.used", Valid: true}, Lim: 1})
	if err != nil || len(rows) == 0 {
		return err
	}
	return svc.s.W().TxNamed(ctx, "opauth.breakglass_ack", func(tx *store.Tx) error {
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingBreakGlassAck, Value: strconv.FormatInt(rows[0].Seq, 10),
			UpdatedAt: tx.NowMicros(), UpdatedBy: sql.NullString{String: actor.ID, Valid: true}}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "breakglass.acknowledged", Details: map[string]any{"through_seq": rows[0].Seq}})
		return err
	})
}

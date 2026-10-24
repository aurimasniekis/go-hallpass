package recording

import (
	"context"
	"log/slog"

	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// RewrapSegments moves segment DEKs to the active recording key after a rotation (HP-CRY-002, PLAN §13.1/§13.4) and
// returns how many segments were rewrapped. For a segment with a file, hprec.RewrapSlot writes the inactive key slot
// under the active key and fsyncs it, then the database copy of the wrapped DEK is updated (compare-and-set, so a
// concurrent change wins). A segment without a file (missing, or failed before its file existed) has only its database
// copy rewrapped, which startup slot repair writes back if the file ever returns. Open segments are skipped until
// they are finalized. Problems with single segments are logged and do not stop the run. Run it until it returns 0;
// then the old recording key version no longer protects any segment and `hallpass keys retire` accepts it.
func (svc *Service) RewrapSegments(ctx context.Context, batch int) (int, error) {
	if batch <= 0 {
		batch = 500
	}
	active := recordingKeyID(svc.kr.ActiveVersion(keyring.PurposeRecording))
	done := 0
	after := ""
	for {
		rows, err := svc.s.R().SegmentsNeedingRewrap(ctx, db.SegmentsNeedingRewrapParams{ActiveKeyID: active, After: after, Lim: int64(batch)})
		if err != nil {
			return done, err
		}
		for _, seg := range rows {
			after = seg.ID
			if err := ctx.Err(); err != nil {
				return done, err
			}
			ok, err := svc.rewrapSegment(ctx, seg)
			if err != nil {
				svc.log.Warn("recording segment key not rewrapped", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
				continue
			}
			if ok {
				done++
			}
		}
		if len(rows) < batch {
			return done, nil
		}
	}
}

func (svc *Service) rewrapSegment(ctx context.Context, seg db.RecordingSegment) (bool, error) {
	path, err := svc.SegmentFile(seg)
	if err != nil {
		return false, err
	}
	file := ""
	for _, p := range []string{path, path + hprec.PartialSuffix} {
		if exists(p) {
			file = p
			break
		}
	}
	var keyID string
	var wrapped []byte
	if file != "" {
		ns, err := hprec.RewrapSlot(file, svc.wrapper, svc.wrapper, expectations(seg)...)
		if err != nil {
			return false, err
		}
		keyID, wrapped = ns.KeyID, ns.Wrapped
	} else {
		if len(seg.HeaderSha256) != 32 {
			return false, hprec.ErrInvalidSlot
		}
		var h [32]byte
		copy(h[:], seg.HeaderSha256)
		aad := hprec.DEKAAD(seg.ID, h)
		dek, err := svc.wrapper.Unwrap(seg.KeyID, seg.WrappedDek, aad)
		if err != nil {
			return false, err
		}
		keyID, wrapped, err = svc.wrapper.Wrap(dek, aad)
		clear(dek)
		if err != nil {
			return false, err
		}
	}
	var n int64
	err = svc.s.W().TxNamed(ctx, "recording.rewrap", func(tx *store.Tx) error {
		var uerr error
		n, uerr = tx.Q.UpdateSegmentKey(ctx, db.UpdateSegmentKeyParams{KeyID: keyID, WrappedDek: wrapped, ID: seg.ID,
			OldKeyID: seg.KeyID, OldWrappedDek: seg.WrappedDek})
		return uerr
	})
	return n == 1, err
}

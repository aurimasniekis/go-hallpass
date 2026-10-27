package access

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// ConnectionInfo describes an authenticated inbound SSH connection.
type ConnectionInfo struct {
	AgentID       string
	KeyID         string
	ClientUser    string // untrusted; recorded only (HP-SSH-002)
	ClientVersion string
	SourceIP      string
	// OperatorID names the administrator of a web terminal connection (AgentID is ConsoleAgentID).
	OperatorID string
}

// OpenConnection records an authenticated agent connection.
func (svc *Service) OpenConnection(ctx context.Context, in ConnectionInfo) (string, error) {
	id := ids.New(ids.Connection)
	err := svc.s.W().TxNamed(ctx, "access.open_connection", func(tx *store.Tx) error {
		return tx.Q.InsertConnection(ctx, db.InsertConnectionParams{
			ID: id, AgentID: in.AgentID, AgentKeyID: in.KeyID, ClientUser: truncate(in.ClientUser, 256), ClientVersion: truncate(in.ClientVersion, 256),
			SourceIp: in.SourceIP, OpenedAt: tx.NowMicros(), BootID: svc.opts.BootID,
			OperatorID: sql.NullString{String: in.OperatorID, Valid: in.OperatorID != ""},
		})
	})
	return id, err
}

// NoteConnectionSession records the first agent session a connection names (for the activity views and audit).
// Failures are ignored: the session is bookkeeping here, enforced on requests and grants.
func (svc *Service) NoteConnectionSession(ctx context.Context, connID, agentSession string) {
	if agentSession == "" {
		return
	}
	_ = svc.s.W().TxNamed(ctx, "access.connection_session", func(tx *store.Tx) error {
		return tx.Q.SetConnectionAgentSession(ctx, db.SetConnectionAgentSessionParams{AgentSession: agentSession, ID: connID})
	})
}

// CloseConnection records the end of a connection and adds connection.closed to every session it touched.
func (svc *Service) CloseConnection(ctx context.Context, connID, reason string) error {
	sessions, err := svc.s.R().SessionsForConnection(ctx, connID)
	if err != nil {
		return err
	}
	seqs := map[string]int64{}
	for _, sid := range sessions {
		if seqs[sid], err = svc.seq.Next(ctx, sid, 1); err != nil {
			return err
		}
	}
	return svc.s.W().TxNamed(ctx, "access.close_connection", func(tx *store.Tx) error {
		n, err := tx.Q.CloseConnection(ctx, db.CloseConnectionParams{ClosedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			CloseReason: sql.NullString{String: reason, Valid: true}, ID: connID})
		if err != nil || n == 0 {
			return err
		}
		for _, sid := range sessions {
			if err := svc.appendTimeline(ctx, tx, TimelineEvent{SessionID: sid, Seq: seqs[sid], Type: EvConnClosed, ConnectionID: connID,
				Data: map[string]any{"reason": reason}}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Channel kinds.
const (
	KindShell = "shell"
	KindExec  = "exec"
)

// RegisterInput asks to start destination activity under a grant.
type RegisterInput struct {
	ConnectionID string
	AgentID      string
	KeyID        string
	GrantID      string
	Kind         string // shell | exec
	PTY          bool
	// GitService and GitRepo describe a git operation on a git remote (an exec of the git service). The role must
	// grant git-write for git-receive-pack and git-read otherwise, instead of exec.
	GitService string
	GitRepo    string
	// Subsystem is "sftp" for a file transfer; the role must grant file-transfer instead of exec.
	Subsystem string
	// APIHost is the API host of a tunnel through the API proxy; the role must grant api instead of exec.
	APIHost string
	// OperatorID is the administrator of a web terminal (ADR-0055); it must match the grant's.
	OperatorID string
	// AgentSession is the connection's agent session; it must match the grant's.
	AgentSession string
}

// ChannelReg is a registered (opening) channel.
type ChannelReg struct {
	ChannelID string
	SessionID string
	Grant     *Grant
	Role      *inventory.Role
}

// ErrCapability is returned when the role does not grant the requested channel type.
var ErrCapability = apperr.New(apperr.CodeForbidden, "this role does not permit the requested session type")

// RegisterChannel revalidates everything needed to start a new destination channel and reserves a concurrency slot,
// atomically in one writer transaction (HP-SSH-025, HP-GRT-006). It checks the grant (active, not expiring within
// MinRemainingToConnect), lockdown, the current policy for agent/server/role (which also covers disabled objects),
// the authenticating key, the role capability and concurrency limits.
func (svc *Service) RegisterChannel(ctx context.Context, in RegisterInput) (*ChannelReg, error) {
	if in.Kind != KindShell && in.Kind != KindExec {
		return nil, apperr.New(apperr.CodeInvalid, "invalid channel kind")
	}
	if svc.opts.StorageReserve != nil {
		if err := svc.opts.StorageReserve(); err != nil {
			// Fail closed below the free-space reserve (HP-OPS-006, PLAN §4.5): no new activity that must be recorded.
			svc.log.Warn("channel refused: storage below reserve", obs.Err(err))
			return nil, ErrStorageUnavailable
		}
	}
	sess, err := svc.s.R().GetSessionByGrant(ctx, in.GrantID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAccessEnded
	} else if err != nil {
		return nil, err
	}
	seq, err := svc.seq.Next(ctx, sess.ID, 1)
	if err != nil {
		return nil, err
	}
	var reg *ChannelReg
	err = svc.withPolicy(ctx, "access.register_channel", func(tx *store.Tx, snap *policy.Snapshot) error {
		reg = nil
		gr, err := tx.Q.GetGrant(ctx, in.GrantID)
		if err != nil {
			return err
		}
		g := grantFromRow(gr)
		if g.AgentID != in.AgentID || g.OperatorID != in.OperatorID || g.AgentSession != in.AgentSession {
			return ErrNotFoundOrForbidden
		}
		if snap.Lockdown {
			return ErrLockdown
		}
		if !g.ActiveAt(tx.Now.Add(svc.opts.MinRemainingToConnect)) {
			return ErrAccessEnded
		}
		if g.Console() {
			// A web terminal: no agent key or agent rules; the server and role must still be live and the operator
			// still an enabled administrator (ADR-0055).
			if !snap.EvaluateConsole(g.ServerID, g.RoleID).Requestable() {
				return ErrAccessEnded
			}
			if err := consoleOperator(ctx, tx.Q, policy.OperatorInfo{ID: g.OperatorID}); err != nil {
				return ErrAccessEnded
			}
		} else {
			if !snap.Evaluate(g.AgentID, g.ServerID, g.RoleID).Requestable() {
				return ErrAccessEnded
			}
			key, err := tx.Q.GetAgentKey(ctx, in.KeyID)
			if err != nil || key.State != "active" || key.AgentID != in.AgentID {
				return ErrAccessEnded
			}
		}
		s, err := tx.Q.GetSession(ctx, sess.ID)
		if err != nil {
			return err
		}
		if s.State != "open" {
			return ErrAccessEnded
		}
		roleRow, err := tx.Q.GetRole(ctx, g.RoleID)
		if err != nil {
			return err
		}
		role := inventory.RoleFromRow(roleRow)
		need := inventory.CapExec
		switch {
		case in.GitService == gitproto.ReceivePack:
			need = inventory.CapGitWrite
		case in.GitService != "":
			need = inventory.CapGitRead
		case in.Subsystem == "sftp":
			need = inventory.CapFileTransfer
		case in.APIHost != "":
			need = inventory.CapAPI
		case in.Kind == KindShell:
			need = inventory.CapShell
		}
		if (in.GitService != "" || in.Subsystem != "" || in.APIHost != "") && (in.Kind != KindExec || in.PTY) {
			return ErrCapability
		}
		if !slices.Contains(g.Capabilities, need) || !role.Has(need) || (in.PTY && (!role.Has(inventory.CapPTY) || !slices.Contains(g.Capabilities, inventory.CapPTY))) {
			return ErrCapability
		}
		total, err := tx.Q.CountLiveChannelsForRole(ctx, g.RoleID)
		if err != nil {
			return err
		}
		if total >= int64(role.MaxConcurrent) {
			return ErrConcurrencyLimit
		}
		if g.Console() {
			// All web terminals share one agent; limit them per operator instead.
			mine, err := tx.Q.CountLiveChannelsForOperator(ctx, sql.NullString{String: g.OperatorID, Valid: true})
			if err != nil {
				return err
			}
			if mine >= MaxConsoleChannelsPerOperator {
				return ErrConcurrencyLimit
			}
		} else {
			mine, err := tx.Q.CountLiveChannelsForAgentRole(ctx, db.CountLiveChannelsForAgentRoleParams{AgentID: g.AgentID, RoleID: g.RoleID})
			if err != nil {
				return err
			}
			if mine >= int64(role.MaxConcurrentPerAgent) {
				return ErrConcurrencyLimit
			}
		}
		firstOnConn, err := tx.Q.CountChannelsForConnectionInSession(ctx, db.CountChannelsForConnectionInSessionParams{ConnectionID: in.ConnectionID, AccessSessionID: sess.ID})
		if err != nil {
			return err
		}
		chID := ids.New(ids.Channel)
		if err := tx.Q.InsertChannel(ctx, db.InsertChannelParams{
			ID: chID, ConnectionID: in.ConnectionID, AccessSessionID: sess.ID, GrantID: g.ID, AgentID: g.AgentID, RoleID: g.RoleID,
			Kind: in.Kind, Pty: b2i(in.PTY), OpenedAt: tx.NowMicros(), BootID: svc.opts.BootID,
			GitService: optString(in.GitService), GitRepo: optString(in.GitRepo), Subsystem: optString(in.Subsystem),
			ApiHost: optString(in.APIHost),
		}); err != nil {
			return err
		}
		if firstOnConn == 0 {
			if err := svc.appendTimeline(ctx, tx, TimelineEvent{SessionID: sess.ID, Seq: seq, Type: EvConnOpened, ConnectionID: in.ConnectionID,
				Data: map[string]any{"key_id": in.KeyID}}); err != nil {
				return err
			}
		}
		g.SessionID = sess.ID
		reg = &ChannelReg{ChannelID: chID, SessionID: sess.ID, Grant: g, Role: role}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// ActivateChannel marks a registered channel active once the destination channel is open and recording is
// established, recording which credential was used.
func (svc *Service) ActivateChannel(ctx context.Context, reg *ChannelReg, credentialRef string, data map[string]any) error {
	seq, err := svc.seq.Next(ctx, reg.SessionID, 1)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "access.activate_channel", func(tx *store.Tx) error {
		n, err := tx.Q.ActivateChannel(ctx, db.ActivateChannelParams{CredentialRef: sql.NullString{String: credentialRef, Valid: credentialRef != ""}, ID: reg.ChannelID})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrAccessEnded
		}
		svc.publish(tx, eventbus.TopicActivityStarted, reg.ChannelID, reg.SessionID)
		return svc.appendTimeline(ctx, tx, TimelineEvent{SessionID: reg.SessionID, Seq: seq, Type: EvChannelOpened, ChannelID: reg.ChannelID, Data: data})
	})
}

// CloseInfo describes how a channel ended.
type CloseInfo struct {
	Failed bool // never became active
	Reason string
	// Detail is a classified, address-free explanation of a failure or gateway termination (never raw error text).
	Detail string
	// GatewayCode is the 80-90 exit code the gateway sent to the agent (0: the destination's own status).
	GatewayCode int
	ExitStatus  *int
	ExitSignal  string
	Data        map[string]any
}

// CloseChannel records the end of a channel and frees its concurrency slot.
func (svc *Service) CloseChannel(ctx context.Context, reg *ChannelReg, ci CloseInfo) error {
	seq, err := svc.seq.Next(ctx, reg.SessionID, 1)
	if err != nil {
		return err
	}
	ctx = context.WithoutCancel(ctx)
	return svc.s.W().TxNamed(ctx, "access.close_channel", func(tx *store.Tx) error {
		state, evType := "closed", EvChannelExited
		if ci.Failed {
			state, evType = "failed", EvChannelFailed
		}
		st := sql.NullInt64{}
		if ci.ExitStatus != nil {
			st = sql.NullInt64{Int64: int64(*ci.ExitStatus), Valid: true}
		}
		n, err := tx.Q.EndChannel(ctx, db.EndChannelParams{State: state, ExitStatus: st, ExitSignal: sql.NullString{String: ci.ExitSignal, Valid: ci.ExitSignal != ""},
			Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, CloseReason: sql.NullString{String: ci.Reason, Valid: true},
			CloseDetail: sql.NullString{String: ci.Detail, Valid: ci.Detail != ""}, GatewayExitCode: sql.NullInt64{Int64: int64(ci.GatewayCode), Valid: ci.GatewayCode != 0},
			ID: reg.ChannelID})
		if err != nil || n == 0 {
			return err
		}
		data := map[string]any{"reason": ci.Reason}
		if ci.Detail != "" {
			data["detail"] = ci.Detail
		}
		if ci.GatewayCode != 0 {
			data["gateway_exit_code"] = ci.GatewayCode
		}
		for k, v := range ci.Data {
			data[k] = v
		}
		if ci.ExitStatus != nil {
			data["exit_status"] = *ci.ExitStatus
		}
		if ci.ExitSignal != "" {
			data["exit_signal"] = ci.ExitSignal
		}
		svc.publish(tx, eventbus.TopicActivityEnded, reg.ChannelID, reg.SessionID)
		return svc.appendTimeline(ctx, tx, TimelineEvent{SessionID: reg.SessionID, Seq: seq, Type: evType, ChannelID: reg.ChannelID, Data: data})
	})
}

// AppendSessionEvent records a lifecycle event (e.g. exec.requested metadata, recording.failed) on a channel.
func (svc *Service) AppendSessionEvent(ctx context.Context, reg *ChannelReg, typ, segmentID string, data map[string]any) error {
	seq, err := svc.seq.Next(ctx, reg.SessionID, 1)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "access.session_event", func(tx *store.Tx) error {
		return svc.appendTimeline(ctx, tx, TimelineEvent{SessionID: reg.SessionID, Seq: seq, Type: typ, ChannelID: reg.ChannelID, SegmentID: segmentID, Data: data})
	})
}

// LiveChannels lists opening/active channels (operator activity view, HP-SES-005).
func (svc *Service) LiveChannels(ctx context.Context) ([]db.SshChannel, error) {
	return svc.s.R().LiveChannels(ctx)
}

// TimelineEntry is a stored timeline event.
type TimelineEntry struct {
	ID           string         `json:"id"`
	Seq          int64          `json:"seq,omitempty"`
	Type         string         `json:"type"`
	At           time.Time      `json:"at"`
	ConnectionID string         `json:"connection_id,omitempty"`
	ChannelID    string         `json:"channel_id,omitempty"`
	SegmentID    string         `json:"segment_id,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// optString maps "" to NULL.
func optString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

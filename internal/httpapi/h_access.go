package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// ---- policy

func (s *Server) ListPolicyRules(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Policy.ListRules(c.R.Context())
	if err != nil {
		return nil, err
	}
	out := make([]ruleDTO, len(v))
	for i, r := range v {
		out[i] = rule(r)
	}
	return ok(list(out))
}

func (s *Server) CreatePolicyRule(c *gen.Call) (*gen.Result, error) {
	var in ruleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	r, err := s.d.Policy.CreateRule(c.R.Context(), actor(c), in.rule())
	if err != nil {
		return nil, err
	}
	return created(rule(*r))
}

func (s *Server) GetPolicyRule(c *gen.Call) (*gen.Result, error) {
	r, err := s.d.Policy.GetRule(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(rule(*r))
}

func (s *Server) UpdatePolicyRule(c *gen.Call) (*gen.Result, error) {
	var in ruleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	r := in.rule()
	r.Version = v
	out, err := s.d.Policy.UpdateRule(c.R.Context(), actor(c), c.R.PathValue("id"), r)
	if err != nil {
		return nil, err
	}
	return ok(rule(*out))
}

func (s *Server) DeletePolicyRule(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Policy.DeleteRule(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) ListApproverRules(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Policy.ListApproverRules(c.R.Context())
	if err != nil {
		return nil, err
	}
	out := make([]approverRuleDTO, len(v))
	for i, r := range v {
		out[i] = approverRuleDTO{ApproverRule: r, MaxDuration: secs(r.MaxDuration)}
	}
	return ok(list(out))
}

func (s *Server) CreateApproverRule(c *gen.Call) (*gen.Result, error) {
	var in approverRuleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	r, err := s.d.Policy.CreateApproverRule(c.R.Context(), actor(c), in.rule())
	if err != nil {
		return nil, err
	}
	return created(approverRuleDTO{ApproverRule: *r, MaxDuration: secs(r.MaxDuration)})
}

func (s *Server) UpdateApproverRule(c *gen.Call) (*gen.Result, error) {
	var in approverRuleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	r := in.rule()
	r.Version = v
	out, err := s.d.Policy.UpdateApproverRule(c.R.Context(), actor(c), c.R.PathValue("id"), r)
	if err != nil {
		return nil, err
	}
	return ok(approverRuleDTO{ApproverRule: *out, MaxDuration: secs(out.MaxDuration)})
}

func (s *Server) DeleteApproverRule(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Policy.DeleteApproverRule(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) GetPolicyVersion(c *gen.Call) (*gen.Result, error) {
	snap, err := s.d.Engine.Current(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(map[string]int64{"version": snap.Version})
}

// ---- requests

type page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func (s *Server) ListRequests(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(c.R.URL.Query().Get("cursor"))
	if err != nil {
		return nil, err
	}
	state, err := queryEnum(c.R, "state", access.ReqPending, access.ReqApproved, access.ReqDenied, access.ReqExpired, access.ReqCanceled)
	if err != nil {
		return nil, err
	}
	q := c.R.URL.Query()
	p := db.ListRequestsPageParams{State: nullStr(state), AgentID: nullStr(q.Get("agent_id")), ServerID: nullStr(q.Get("server_id")), Lim: lim + 1}
	if cur != nil {
		p.BeforeAt, p.BeforeID = sql.NullInt64{Int64: cur.At, Valid: true}, nullStr(cur.ID)
	}
	rows, err := s.d.Store.R().ListRequestsPage(c.R.Context(), p)
	if err != nil {
		return nil, err
	}
	out := page[requestDTO]{Items: []requestDTO{}}
	for i, r := range rows {
		if int64(i) == lim {
			last := rows[i-1]
			out.NextCursor = encodeCursor(cursor{At: last.CreatedAt, ID: last.ID})
			break
		}
		out.Items = append(out.Items, s.request(c, requestFromRow(r)))
	}
	return ok(out)
}

func (s *Server) GetRequest(c *gen.Call) (*gen.Result, error) {
	r, err := s.d.Access.GetRequest(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(s.request(c, r))
}

type decisionDTO struct {
	Request requestDTO    `json:"request"`
	Grant   *access.Grant `json:"grant"`
}

// decide records a web decision; approver scope, self-approval and duration bounds are enforced by access.Decide
// in the same transaction that creates the grant (HP-RBAC-003).
func (s *Server) decide(c *gen.Call, approve bool) (*gen.Result, error) {
	var in struct {
		Duration int64  `json:"duration"`
		Comment  string `json:"comment"`
	}
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	if !approve && in.Duration != 0 {
		return nil, apperr.New(apperr.CodeInvalid, "duration applies to approvals only")
	}
	res, err := s.d.Access.Decide(c.R.Context(), access.DecideInput{RequestID: c.R.PathValue("id"), Approve: approve,
		Duration: time.Duration(in.Duration) * time.Second, Operator: operatorInfo(c), Channel: access.ChannelWeb, Comment: in.Comment,
		IdempotencyKey: c.R.Header.Get("Idempotency-Key")})
	if err != nil {
		return nil, err
	}
	return ok(decisionDTO{Request: s.request(c, res.Request), Grant: res.Grant})
}

func (s *Server) ApproveRequest(c *gen.Call) (*gen.Result, error) { return s.decide(c, true) }
func (s *Server) DenyRequest(c *gen.Call) (*gen.Result, error)    { return s.decide(c, false) }

func (s *Server) CancelRequest(c *gen.Call) (*gen.Result, error) {
	r, err := s.d.Access.CancelByOperator(c.R.Context(), operatorInfo(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(s.request(c, r))
}

// ---- grants

func (s *Server) ListGrants(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(c.R.URL.Query().Get("cursor"))
	if err != nil {
		return nil, err
	}
	state, err := queryEnum(c.R, "state", access.GrantActive, access.GrantExpired, access.GrantRevoked)
	if err != nil {
		return nil, err
	}
	q := c.R.URL.Query()
	p := db.ListGrantsPageParams{State: nullStr(state), AgentID: nullStr(q.Get("agent_id")), ServerID: nullStr(q.Get("server_id")), Lim: lim + 1}
	if cur != nil {
		p.BeforeAt, p.BeforeID = sql.NullInt64{Int64: cur.At, Valid: true}, nullStr(cur.ID)
	}
	rows, err := s.d.Store.R().ListGrantsPage(c.R.Context(), p)
	if err != nil {
		return nil, err
	}
	out := page[*access.Grant]{Items: []*access.Grant{}}
	for i, r := range rows {
		if int64(i) == lim {
			last := rows[i-1]
			out.NextCursor = encodeCursor(cursor{At: last.StartsAt, ID: last.ID})
			break
		}
		out.Items = append(out.Items, grantFromRow(r))
	}
	return ok(out)
}

func (s *Server) GetGrant(c *gen.Call) (*gen.Result, error) {
	g, err := s.d.Access.GetGrant(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(g)
}

func (s *Server) RevokeGrant(c *gen.Call) (*gen.Result, error) {
	var in reasonBody
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	g, err := s.d.Access.RevokeGrant(c.R.Context(), operatorInfo(c), c.R.PathValue("id"), in.Reason)
	if err != nil {
		return nil, err
	}
	return ok(g)
}

// ---- access sessions

func (s *Server) ListAccessSessions(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(c.R.URL.Query().Get("cursor"))
	if err != nil {
		return nil, err
	}
	state, err := queryEnum(c.R, "state", "open", "closing", "closed")
	if err != nil {
		return nil, err
	}
	q := c.R.URL.Query()
	p := db.ListSessionsPageParams{State: nullStr(state), AgentID: nullStr(q.Get("agent_id")), ServerID: nullStr(q.Get("server_id")), Lim: lim + 1}
	if cur != nil {
		p.BeforeAt, p.BeforeID = sql.NullInt64{Int64: cur.At, Valid: true}, nullStr(cur.ID)
	}
	rows, err := s.d.Store.R().ListSessionsPage(c.R.Context(), p)
	if err != nil {
		return nil, err
	}
	out := page[sessionDTO]{Items: []sessionDTO{}}
	for i, r := range rows {
		if int64(i) == lim {
			last := rows[i-1]
			out.NextCursor = encodeCursor(cursor{At: last.OpenedAt, ID: last.ID})
			break
		}
		out.Items = append(out.Items, sessionFromRow(r))
	}
	return ok(out)
}

func notFound(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.New(apperr.CodeNotFound, "%s not found", what)
	}
	return err
}

func (s *Server) GetAccessSession(c *gen.Call) (*gen.Result, error) {
	ctx := c.R.Context()
	r, err := s.d.Store.R().GetSessionDetail(ctx, c.R.PathValue("id"))
	if err != nil {
		return nil, notFound(err, "session")
	}
	dto := sessionFromRow(db.ListSessionsPageRow(r))
	total, live, err := s.d.Access.SessionChannelCounts(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	dto.ChannelsTotal, dto.ChannelsLive = &total, &live
	return ok(dto)
}

func (s *Server) GetSessionTimeline(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	after := int64(0)
	if v := c.R.URL.Query().Get("after_seq"); v != "" {
		if after, err = strconv.ParseInt(v, 10, 64); err != nil || after < 0 {
			return nil, apperr.New(apperr.CodeInvalid, "invalid after_seq")
		}
	}
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if _, err := s.d.Store.R().GetSession(ctx, id); err != nil {
		return nil, notFound(err, "session")
	}
	rows, err := s.d.Store.R().TimelinePage(ctx, db.TimelinePageParams{SessionID: sql.NullString{String: id, Valid: true},
		AfterSeq: sql.NullInt64{Int64: after, Valid: true}, Lim: lim + 1})
	if err != nil {
		return nil, err
	}
	out := struct {
		Items        []timelineDTO `json:"items"`
		NextAfterSeq *int64        `json:"next_after_seq"`
	}{Items: []timelineDTO{}}
	for i, e := range rows {
		if int64(i) == lim {
			out.NextAfterSeq = &rows[i-1].Seq.Int64
			break
		}
		out.Items = append(out.Items, timeline(e))
	}
	return ok(out)
}

func (s *Server) ListSessionChannels(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if _, err := s.d.Store.R().GetSession(ctx, id); err != nil {
		return nil, notFound(err, "session")
	}
	rows, err := s.d.Store.R().ChannelsForSessionAPI(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]channelDTO, len(rows))
	for i, ch := range rows {
		out[i] = channel(ch)
	}
	return ok(list(out))
}

func (s *Server) ListSessionSegments(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if _, err := s.d.Store.R().GetSession(ctx, id); err != nil {
		return nil, notFound(err, "session")
	}
	rows, err := s.d.Store.R().SegmentsForSession(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]segmentDTO, len(rows))
	for i, r := range rows {
		out[i] = segment(r)
	}
	return ok(list(out))
}

// GetRecordingRecords returns decrypted records; every page access is audited (HP-REC-014).
func (s *Server) GetRecordingRecords(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	var from uint64
	if v := c.R.URL.Query().Get("from_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, apperr.New(apperr.CodeInvalid, "invalid from_seq")
		}
		from = n
	}
	seg, err := s.d.Store.R().GetSegment(ctx, id)
	if err != nil {
		return nil, notFound(err, "recording")
	}
	if seg.State == "deleted" || seg.State == "missing" || seg.State == "failed" {
		return nil, apperr.New(apperr.CodeNotFound, "recording is not available (%s)", seg.State)
	}
	p, err := s.d.Recording.ReadPage(ctx, id, from, 256<<10)
	if err != nil {
		return nil, err
	}
	err = s.d.Store.W().TxNamed(ctx, "api.recording_played", func(tx *store.Tx) error {
		_, err := s.d.Audit.Append(ctx, tx, audit.Event{Actor: actor(c), Action: "recording.played", Target: audit.Target{Type: "recording_segment", ID: id},
			SourceIP: s.clientIP(c.R), Details: map[string]any{"session_id": seg.AccessSessionID, "from_seq": from, "records": len(p.Records)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return ok(recordPage(id, p))
}

// ---- activities

func (s *Server) ListActivities(c *gen.Call) (*gen.Result, error) {
	rows, err := s.d.Access.LiveChannels(c.R.Context())
	if err != nil {
		return nil, err
	}
	out := make([]channelDTO, len(rows))
	for i, ch := range rows {
		out[i] = channel(ch)
	}
	return ok(list(out))
}

// TerminateActivity ends one live channel. Approvers need approval authority for its target (in scope).
func (s *Server) TerminateActivity(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	ch, err := s.d.Store.R().GetChannel(ctx, id)
	if err != nil {
		return nil, notFound(err, "activity")
	}
	if !c.Principal.HasRole(opauth.RoleAdministrator) {
		g, err := s.d.Access.GetGrant(ctx, ch.GrantID)
		if err != nil {
			return nil, err
		}
		snap, err := s.d.Engine.Current(ctx)
		if err != nil {
			return nil, err
		}
		if chk := snap.CanApprove(operatorInfo(c), g.AgentID, g.ServerID, g.RoleID, 0); !chk.Allowed {
			return nil, apperr.New(apperr.CodeForbidden, "not permitted to terminate this activity")
		}
	}
	terminated := s.d.Enforcer.Terminate(id, access.ReasonOperator)
	err = s.d.Store.W().TxNamed(ctx, "api.activity_terminate", func(tx *store.Tx) error {
		_, err := s.d.Audit.Append(ctx, tx, audit.Event{Actor: actor(c), Action: "activity.terminated", Target: audit.Target{Type: "channel", ID: id},
			SourceIP: s.clientIP(c.R), Details: map[string]any{"live": terminated}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &gen.Result{Status: http.StatusAccepted, Body: map[string]bool{"terminated": terminated}}, nil
}

// ---- audit

func (s *Server) ListAuditEvents(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(c.R.URL.Query().Get("cursor"))
	if err != nil {
		return nil, err
	}
	q := c.R.URL.Query()
	p := db.ListAuditPageParams{Action: nullStr(q.Get("action")), TargetID: nullStr(q.Get("target_id")), ActorID: nullStr(q.Get("actor_id")), Lim: lim + 1}
	if cur != nil {
		p.BeforeSeq = sql.NullInt64{Int64: cur.Seq, Valid: true}
	}
	rows, err := s.d.Store.R().ListAuditPage(c.R.Context(), p)
	if err != nil {
		return nil, err
	}
	out := page[auditDTO]{Items: []auditDTO{}}
	for i, e := range rows {
		if int64(i) == lim {
			out.NextCursor = encodeCursor(cursor{Seq: rows[i-1].Seq})
			break
		}
		out.Items = append(out.Items, auditEvent(e))
	}
	return ok(out)
}

func (s *Server) VerifyAuditChain(c *gen.Call) (*gen.Result, error) {
	res, err := audit.Verify(c.R.Context(), s.d.Store.R())
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"ok": res.OK, "events": res.Events, "problem": res.Problem})
}

// ---- system

func (s *Server) systemStatus(ctx context.Context) (map[string]any, error) {
	st, err := s.d.Store.R().GetPolicyState(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := s.d.Store.R().CountPendingAll(ctx)
	if err != nil {
		return nil, err
	}
	active, err := s.d.Store.R().CountActiveGrants(ctx)
	if err != nil {
		return nil, err
	}
	live, err := s.d.Access.LiveChannels(ctx)
	if err != nil {
		return nil, err
	}
	storageOK := s.d.Store.Health() == nil || s.d.Store.Health().AcceptsWrites(ctx)
	bg, bgAt, err := s.d.Auth.BreakGlassAlert(ctx)
	if err != nil {
		return nil, err
	}
	var bgTime *time.Time
	if bg {
		bgTime = &bgAt
	}
	return map[string]any{"lockdown": st.Lockdown == 1, "version": buildinfo.Get().Version, "boot_id": s.d.BootID, "pending_requests": pending,
		"active_grants": active, "live_channels": len(live), "storage_ok": storageOK, "policy_version": st.Version,
		"breakglass_alert": bg, "breakglass_at": bgTime}, nil
}

func (s *Server) GetSystemStatus(c *gen.Call) (*gen.Result, error) {
	st, err := s.systemStatus(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(st)
}

func (s *Server) setLockdown(c *gen.Call, on bool) (*gen.Result, error) {
	if err := s.d.Access.SetLockdown(c.R.Context(), actor(c), on); err != nil {
		return nil, err
	}
	if on {
		s.d.Enforcer.TerminateAll(access.ReasonLockdown)
	}
	return s.GetSystemStatus(c)
}

func (s *Server) EnableLockdown(c *gen.Call) (*gen.Result, error) { return s.setLockdown(c, true) }
func (s *Server) LiftLockdown(c *gen.Call) (*gen.Result, error)   { return s.setLockdown(c, false) }

func (s *Server) ListGatewayHostKeys(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.GatewayHostKeys(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

type point struct {
	T time.Time `json:"t"`
	N int       `json:"n"`
}

func buckets(since time.Time, bucket time.Duration, n int, times []int64) []point {
	out := make([]point, n)
	for i := range out {
		out[i].T = since.Add(time.Duration(i) * bucket).UTC()
	}
	for _, t := range times {
		i := int(time.UnixMicro(t).Sub(since) / bucket)
		if i >= 0 && i < n {
			out[i].N++
		}
	}
	return out
}

func (s *Server) GetStatsOverview(c *gen.Call) (*gen.Result, error) {
	rng, err := queryEnum(c.R, "range", "24h", "7d", "30d")
	if err != nil {
		return nil, err
	}
	if rng == "" {
		rng = "24h"
	}
	span, bucket := 24*time.Hour, time.Hour
	switch rng {
	case "7d":
		span, bucket = 7*24*time.Hour, 6*time.Hour
	case "30d":
		span, bucket = 30*24*time.Hour, 24*time.Hour
	}
	now := s.o.Clock.Now().UTC()
	since := now.Add(-span).Truncate(bucket)
	n := int(now.Sub(since)/bucket) + 1
	ctx := c.R.Context()
	reqs, err := s.d.Store.R().RequestTimesSince(ctx, since.UnixMicro())
	if err != nil {
		return nil, err
	}
	sess, err := s.d.Store.R().SessionTimesSince(ctx, since.UnixMicro())
	if err != nil {
		return nil, err
	}
	byState := map[string]int{}
	reqTimes := make([]int64, len(reqs))
	for i, r := range reqs {
		reqTimes[i] = r.CreatedAt
		byState[r.State]++
	}
	return ok(map[string]any{"range": rng, "bucket_seconds": int64(bucket / time.Second), "requests_by_state": byState,
		"requests": buckets(since, bucket, n, reqTimes), "sessions": buckets(since, bucket, n, sess)})
}

var _ = policy.LevelVisible

func (s *Server) AcknowledgeBreakGlass(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.AcknowledgeBreakGlass(c.R.Context(), actor(c)); err != nil {
		return nil, err
	}
	return s.GetSystemStatus(c)
}

// exportLimit bounds a session export's decrypted payload.
const exportLimit = 64 << 20

// ExportSessionRecordings exports a session's recordings (HP-REC-014). The default format is a ciphertext bundle
// (exportBundle); format=plaintext returns decrypted records as JSON. Both require recording.export with recent
// authentication and MFA and are audited before the response is written.
func (s *Server) ExportSessionRecordings(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if _, err := s.d.Store.R().GetSession(ctx, id); err != nil {
		return nil, notFound(err, "session")
	}
	switch c.R.URL.Query().Get("format") {
	case "", "bundle":
		return s.exportBundle(c, id)
	case "plaintext":
	default:
		return nil, apperr.New(apperr.CodeInvalid, "format must be bundle or plaintext")
	}
	segs, err := s.d.Store.R().SegmentsForSession(ctx, id)
	if err != nil {
		return nil, err
	}
	type segExport struct {
		SegmentID string      `json:"segment_id"`
		ChannelID string      `json:"channel_id"`
		Ordinal   int64       `json:"ordinal"`
		State     string      `json:"state"`
		Complete  bool        `json:"complete"`
		Records   []recordDTO `json:"records"`
	}
	out := struct {
		SessionID  string      `json:"session_id"`
		ExportedAt time.Time   `json:"exported_at"`
		Truncated  bool        `json:"truncated"`
		Segments   []segExport `json:"segments"`
	}{SessionID: id, ExportedAt: s.o.Clock.Now().UTC(), Segments: []segExport{}}
	total := 0
	for _, seg := range segs {
		if seg.State == "deleted" || seg.State == "missing" || seg.State == "failed" {
			continue
		}
		se := segExport{SegmentID: seg.ID, ChannelID: seg.ChannelID, Ordinal: seg.Ordinal, State: seg.State, Records: []recordDTO{}}
		var from uint64
		for !out.Truncated {
			p, err := s.d.Recording.ReadPage(ctx, seg.ID, from, 256<<10)
			if err != nil {
				return nil, err
			}
			for _, r := range recordPage(seg.ID, p).Records {
				total += len(r.Data)
				if total > exportLimit {
					out.Truncated = true
					break
				}
				se.Records = append(se.Records, r)
			}
			se.Complete = p.Complete
			if !p.More {
				break
			}
			from = p.NextSeq
		}
		out.Segments = append(out.Segments, se)
	}
	err = s.d.Store.W().TxNamed(ctx, "api.recording_exported", func(tx *store.Tx) error {
		_, err := s.d.Audit.Append(ctx, tx, audit.Event{Actor: actor(c), Action: "recording.exported", Target: audit.Target{Type: "access_session", ID: id},
			SourceIP: s.clientIP(c.R), Details: map[string]any{"format": "plaintext", "segments": len(out.Segments), "truncated": out.Truncated}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return ok(out)
}

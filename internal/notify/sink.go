package notify

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// sinkFor binds inbound events to the integration whose webhook received them.
type sinkFor struct {
	svc           *Service
	integrationID string
}

// HandleEvent implements chat.Sink. Adapters only identify the provider user; every authorization decision is
// made here and in access.Decide (HP-NTF-008, G-5).
func (s sinkFor) HandleEvent(ctx context.Context, ev chat.Event) chat.Reply {
	var id *chat.Identity
	switch {
	case ev.Kind == chat.EventInteraction && ev.Interaction != nil:
		id = &ev.Interaction.Identity
	case ev.Kind == chat.EventLink && ev.Link != nil:
		id = &ev.Link.Identity
	case ev.Kind == chat.EventStatus && ev.Status != nil:
		id = &ev.Status.Identity
	}
	if id == nil {
		return chat.Reply{Text: "Unsupported action."}
	}
	// Per provider user limit, after platform verification (HP-NTF-012, PLAN §10.7, SR-40).
	if !s.svc.userActions.Allow(s.integrationID+"|"+id.Workspace+"|"+id.UserID, s.svc.opts.Clock.Now()) {
		s.svc.refuse(ctx, s.integrationID, *id, "chat.action.refused", "rate_limited")
		return chat.Reply{Text: "Too many actions; wait a moment and try again."}
	}
	switch ev.Kind {
	case chat.EventInteraction:
		return chat.Reply{Text: s.svc.interaction(ctx, s.integrationID, *ev.Interaction)}
	case chat.EventLink:
		return chat.Reply{Text: s.svc.link(ctx, s.integrationID, *ev.Link)}
	case chat.EventStatus:
		return chat.Reply{Text: s.svc.status(ctx, *ev.Status)}
	}
	return chat.Reply{Text: "Unsupported action."}
}

// refuse audits a refused chat action or link attempt (PLAN §10.5, SR-41), rate limited per integration, action,
// reason and provider user, and globally, so a flood cannot turn into unbounded audit writes.
func (svc *Service) refuse(ctx context.Context, integrationID string, id chat.Identity, action, reason string) {
	now := svc.opts.Clock.Now()
	key := strings.Join([]string{integrationID, action, reason, id.Workspace, id.UserID}, "|")
	if !svc.refusals.Allow(key, now) || !svc.refusalsAll.Allow("all", now) {
		return
	}
	_ = svc.s.W().TxNamed(context.WithoutCancel(ctx), "notify.refused", func(tx *store.Tx) error {
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorProvider, ID: id.Provider + ":" + id.UserID},
			Action: action, Outcome: audit.OutcomeDenied, Target: audit.Target{Type: "integration", ID: integrationID},
			Details: map[string]any{"reason": reason, "provider": id.Provider, "workspace": id.Workspace, "chat_id": id.ChatID}})
		return err
	})
}

// Rejected implements chat.Sink: refused webhooks are audited, rate limited per reason and provider user (bounded
// table, SR-43). Unsupported updates (ordinary chat messages that are not commands, non-human senders) are not
// security events and are not audited.
func (s sinkFor) Rejected(ctx context.Context, r chat.Rejection) {
	if r.Reason == chat.RejectUnsupported {
		return
	}
	key := fmt.Sprintf("%s|%s|%s|%s", s.integrationID, r.Reason, r.UserID, r.ChatID)
	if !s.svc.rejected.Allow(key, s.svc.opts.Clock.Now()) || !s.svc.refusalsAll.Allow("all", s.svc.opts.Clock.Now()) {
		return
	}
	_ = s.svc.s.W().TxNamed(context.WithoutCancel(ctx), "notify.rejected", func(tx *store.Tx) error {
		_, err := s.svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorProvider, ID: r.Provider + ":" + r.UserID},
			Action: "webhook.rejected", Outcome: audit.OutcomeDenied, Target: audit.Target{Type: "integration", ID: s.integrationID},
			Details: map[string]any{"reason": string(r.Reason), "authenticated": r.Authenticated, "chat_id": r.ChatID}})
		return err
	})
}

// operatorFor resolves a provider identity to an enabled operator through an explicit link (HP-NTF-011).
func (svc *Service) operatorFor(ctx context.Context, id chat.Identity) (*opauth.Operator, error) {
	l, err := svc.s.R().GetProviderLink(ctx, db.GetProviderLinkParams{Provider: id.Provider, Workspace: id.Workspace, ProviderUserID: id.UserID})
	if err != nil {
		return nil, errNotLinked
	}
	op, err := svc.auth.Get(ctx, l.OperatorID)
	if err != nil || !op.Enabled {
		return nil, errNotLinked
	}
	return op, nil
}

var errNotLinked = errors.New("not linked")

// allowDecision applies the per-operator chat decision rate limit (HP-NTF-012).
func (svc *Service) allowDecision(opID string) bool {
	now := svc.opts.Clock.Now()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	recent := slices.DeleteFunc(svc.limiter[opID], func(t time.Time) bool { return now.Sub(t) > time.Minute })
	if len(recent) >= svc.opts.DecisionsPerMinute {
		svc.limiter[opID] = recent
		return false
	}
	svc.limiter[opID] = append(recent, now)
	return true
}

// chatMFA reports whether the operator satisfies the chat MFA requirement: local TOTP enrolled, or a linked SSO
// identity (MFA delegated to the IdP) (PLAN §10.1, R-10).
func (svc *Service) chatMFA(ctx context.Context, op *opauth.Operator) bool {
	if op.MFAEnrolled {
		return true
	}
	ids, err := svc.s.R().ListIdentitiesForOperator(ctx, op.ID)
	return err == nil && len(ids) > 0
}

// interaction handles a button press: the action token is checked (binding, expiry, single use), the provider user
// must map to an operator, and the decision goes through access.Decide with the same checks as the web UI.
func (svc *Service) interaction(ctx context.Context, integrationID string, in chat.Interaction) string {
	refused := func(reason, reply string) string {
		svc.refuse(ctx, integrationID, in.Identity, "chat.action.refused", reason)
		return reply
	}
	if !chat.ValidActionTokenID(in.ActionTokenID) {
		return refused("invalid_token", "This button is not valid.")
	}
	hashes, err := svc.tokenHashes(in.ActionTokenID)
	if err != nil || len(hashes) == 0 {
		return "HallPass could not process this action."
	}
	var (
		h   []byte
		tok db.ActionToken
	)
	err = sql.ErrNoRows
	for _, cand := range hashes {
		if tok, err = svc.s.R().GetActionToken(ctx, cand); err == nil {
			h = cand
			break
		}
	}
	if err != nil || tok.Provider != in.Provider || tok.IntegrationID != integrationID {
		return refused("invalid_token", "This button is not valid.")
	}
	if string(in.Kind) != "" && string(in.Kind) != tok.Action {
		return refused("invalid_token", "This button is not valid.")
	}
	op, err := svc.operatorFor(ctx, in.Identity)
	if err != nil {
		return refused("not_linked", "Your "+in.Provider+" account is not linked to a HallPass approver. Link it from your HallPass profile.")
	}
	if tok.UsedAt.Valid {
		// Idempotent redelivery (HP-NTF-009): report the recorded outcome without side effects.
		return "Already handled: " + tok.Outcome.String + "."
	}
	if !svc.opts.Clock.Now().Before(time.UnixMicro(tok.ExpiresAt)) {
		return refused("expired", "This request has expired.")
	}
	if *svc.opts.ChatRequiresMFA && !svc.chatMFA(ctx, op) {
		return refused("mfa_required", "Chat approvals need MFA: enroll TOTP in HallPass (or sign in with SSO), then try again.")
	}
	if !svc.allowDecision(op.ID) {
		return refused("rate_limited", "Too many decisions; wait a minute and try again.")
	}
	channel := access.ChannelSlack
	if in.Provider == chat.ProviderTelegram {
		channel = access.ChannelTelegram
	}
	dur := time.Duration(tok.DurationS.Int64) * time.Second
	res, err := svc.access.Decide(ctx, access.DecideInput{RequestID: tok.RequestID, Approve: tok.Action == "approve", Duration: dur,
		Operator:       policy.OperatorInfo{ID: op.ID, Roles: op.Roles, Groups: op.Groups, Enabled: op.Enabled, MFAPassed: true},
		Channel:        channel,
		IdempotencyKey: fmt.Sprintf("action:%x", h[:12])})
	if err != nil {
		var conflict *access.ErrConflict
		switch {
		case errors.As(err, &conflict):
			return "This request is already " + conflict.Current.State + "."
		case apperr.CodeOf(err) == apperr.CodeForbidden:
			return refused("forbidden", "You are not permitted to decide this request: "+publicMessage(err))
		case apperr.CodeOf(err) != "":
			return refused("not_possible", "Not possible: "+publicMessage(err))
		}
		svc.log.Error("chat decision failed", "error", err.Error())
		return "HallPass could not record the decision; try the web UI."
	}
	outcome := res.Request.State
	if res.Grant != nil {
		outcome += " for " + chat.FormatDuration(res.Grant.ExpiresAt.Sub(res.Grant.StartsAt))
	}
	_ = svc.s.W().TxNamed(context.WithoutCancel(ctx), "notify.token_used", func(tx *store.Tx) error {
		_, err := tx.Q.UseActionToken(ctx, db.UseActionTokenParams{UsedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			UsedByOperator: sql.NullString{String: op.ID, Valid: true}, Outcome: sql.NullString{String: outcome, Valid: true}, Hash: h})
		return err
	})
	return "Request " + outcome + " by " + op.DisplayName + "."
}

func publicMessage(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	return "unavailable"
}

// status answers "/hallpass status <req>" for linked operators who may read requests.
func (svc *Service) status(ctx context.Context, q chat.StatusQuery) string {
	op, err := svc.operatorFor(ctx, q.Identity)
	if err != nil {
		return "Your account is not linked to a HallPass operator."
	}
	if len(op.Roles) == 0 {
		return "You have no HallPass role."
	}
	r, err := svc.access.GetRequest(ctx, q.RequestID)
	if err != nil {
		return "Request not found."
	}
	return fmt.Sprintf("Request %s is %s (expires %s).", r.ID, r.State, chat.FormatTime(r.ExpiresAt))
}

// ---- provider identity links (HP-NTF-011)

// Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const linkCodeTTL = 10 * time.Minute

func (svc *Service) linkCodeHash(code string) ([]byte, error) {
	return svc.kr.MAC(keyring.PurposeToken, []byte("hallpass/link-code/v1|"+code))
}

// linkCodeHashes are the candidate stored hashes of a link code under every non-retired token key (SR-36).
func (svc *Service) linkCodeHashes(code string) ([][]byte, error) {
	return svc.kr.MACAll(keyring.PurposeToken, []byte("hallpass/link-code/v1|"+code))
}

// IssueLinkCode creates an 8-character single-use code (40 bits, 10 minutes) for the signed-in operator to send to
// the bot (`/link <code>` in Telegram, `/hallpass link <code>` in Slack).
func (svc *Service) IssueLinkCode(ctx context.Context, operatorID, provider string) (string, time.Time, error) {
	if provider != chat.ProviderSlack && provider != chat.ProviderTelegram {
		return "", time.Time{}, invalid("provider must be slack or telegram")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(crockford[int(c)%32])
	}
	code := sb.String()
	h, err := svc.linkCodeHash(code)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := svc.opts.Clock.Now().Add(linkCodeTTL)
	err = svc.s.W().TxNamed(ctx, "notify.link_code", func(tx *store.Tx) error {
		if err := tx.Q.InsertLinkCode(ctx, db.InsertLinkCodeParams{Hash: h, OperatorID: operatorID, Provider: provider, ExpiresAt: exp.UnixMicro(),
			CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: operatorID}, Action: "provider_link.code_issued",
			Details: map[string]any{"provider": provider}})
		return err
	})
	return code, exp, err
}

func normalizeCrockford(s string) string {
	return strings.NewReplacer("-", "", "I", "1", "L", "1", "O", "0").Replace(strings.ToUpper(s))
}

// link consumes a link code. Telegram codes seen outside a private chat are burned and refused. Failed attempts
// are audited (rate limited) as provider_link.failed (SR-41).
func (svc *Service) link(ctx context.Context, integrationID string, lr chat.LinkRequest) string {
	code, valid := chat.NormalizeLinkCode(lr.Code)
	if !valid {
		svc.refuse(ctx, integrationID, lr.Identity, "provider_link.failed", "malformed_code")
		return "That link code is not valid."
	}
	hashes, err := svc.linkCodeHashes(normalizeCrockford(code))
	if err != nil || len(hashes) == 0 {
		return "HallPass could not process the link code."
	}
	var (
		opID string
		h    []byte
	)
	display := truncate(chat.CleanText(lr.UserName, 64), 64)
	err = svc.s.W().TxNamed(ctx, "notify.link", func(tx *store.Tx) error {
		var row db.ProviderLinkCode
		err := sql.ErrNoRows
		for _, cand := range hashes {
			if row, err = tx.Q.UseLinkCode(ctx, db.UseLinkCodeParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Hash: cand}); err == nil {
				h = cand
				break
			}
		}
		if err != nil {
			return errNotLinked
		}
		if row.Provider != lr.Provider {
			return errNotLinked
		}
		if lr.Provider == chat.ProviderTelegram && !lr.PrivateChat {
			return errPublicChat // the code was posted where others can see it: burned (UseLinkCode already consumed it)
		}
		opID = row.OperatorID
		if err := tx.Q.UpsertProviderLink(ctx, db.UpsertProviderLinkParams{Provider: lr.Provider, Workspace: lr.Workspace, ProviderUserID: lr.UserID,
			OperatorID: row.OperatorID, Display: display, LinkedAt: tx.NowMicros(), LinkedVia: "link_code"}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: row.OperatorID}, Action: "provider_link.linked",
			Details: map[string]any{"provider": lr.Provider, "workspace": lr.Workspace, "provider_user_id": lr.UserID, "via": "link_code"}})
		return err
	})
	switch {
	case errors.Is(err, errPublicChat):
		svc.commitBurn(ctx, h)
		svc.refuse(ctx, integrationID, lr.Identity, "provider_link.failed", "public_chat")
		return "Link codes only work in a private chat with the bot. This code is now invalid; create a new one."
	case err != nil:
		svc.refuse(ctx, integrationID, lr.Identity, "provider_link.failed", "invalid_or_expired_code")
		return "That link code is invalid or expired."
	}
	return "Linked to HallPass operator " + svc.operatorDisplay(ctx, opID) + "."
}

var errPublicChat = errors.New("public chat")

// commitBurn consumes a link code whose transaction was rolled back (public-chat refusal).
func (svc *Service) commitBurn(ctx context.Context, h []byte) {
	_ = svc.s.W().TxNamed(ctx, "notify.link_burn", func(tx *store.Tx) error {
		_, err := tx.Q.UseLinkCode(ctx, db.UseLinkCodeParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Hash: h})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
}

func (svc *Service) operatorDisplay(ctx context.Context, id string) string {
	if op, err := svc.auth.Get(ctx, id); err == nil {
		return op.DisplayName
	}
	return id
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ProviderLink is a chat identity linked to an operator.
type ProviderLink struct {
	Provider       string    `json:"provider"`
	Workspace      string    `json:"workspace"`
	ProviderUserID string    `json:"provider_user_id"`
	OperatorID     string    `json:"operator_id"`
	Display        string    `json:"display"`
	LinkedAt       time.Time `json:"linked_at"`
	LinkedVia      string    `json:"linked_via"`
}

// ProviderLinks lists an operator's chat identities.
func (svc *Service) ProviderLinks(ctx context.Context, operatorID string) ([]ProviderLink, error) {
	rows, err := svc.s.R().ListProviderLinks(ctx, operatorID)
	if err != nil {
		return nil, err
	}
	out := make([]ProviderLink, len(rows))
	for i, r := range rows {
		out[i] = ProviderLink{Provider: r.Provider, Workspace: r.Workspace, ProviderUserID: r.ProviderUserID, OperatorID: r.OperatorID, Display: r.Display,
			LinkedAt: time.UnixMicro(r.LinkedAt).UTC(), LinkedVia: r.LinkedVia}
	}
	return out, nil
}

// LinkProviderUser links a chat identity directly (audited admin action with recent authentication at the API).
func (svc *Service) LinkProviderUser(ctx context.Context, actor audit.Actor, operatorID string, l ProviderLink) error {
	if l.Provider != chat.ProviderSlack && l.Provider != chat.ProviderTelegram || l.Workspace == "" || l.ProviderUserID == "" ||
		len(l.Workspace) > 64 || len(l.ProviderUserID) > 64 {
		return invalid("provider, workspace and provider_user_id are required")
	}
	display := truncate(l.Display, 64)
	return svc.s.W().TxNamed(ctx, "notify.link_admin", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOperator(ctx, operatorID); err != nil {
			return apperr.New(apperr.CodeNotFound, "operator not found")
		}
		if err := tx.Q.UpsertProviderLink(ctx, db.UpsertProviderLinkParams{Provider: l.Provider, Workspace: l.Workspace, ProviderUserID: l.ProviderUserID,
			OperatorID: operatorID, Display: display, LinkedAt: tx.NowMicros(), LinkedVia: "admin"}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "provider_link.linked", Target: audit.Target{Type: "operator", ID: operatorID},
			Details: map[string]any{"provider": l.Provider, "workspace": l.Workspace, "provider_user_id": l.ProviderUserID, "via": "admin"}})
		return err
	})
}

// UnlinkProviderUser removes a chat identity; it takes effect immediately.
func (svc *Service) UnlinkProviderUser(ctx context.Context, actor audit.Actor, operatorID, provider, workspace, userID string) error {
	return svc.s.W().TxNamed(ctx, "notify.unlink", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteProviderLink(ctx, db.DeleteProviderLinkParams{Provider: provider, Workspace: workspace, ProviderUserID: userID, OperatorID: operatorID})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "link not found")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "provider_link.unlinked", Target: audit.Target{Type: "operator", ID: operatorID},
			Details: map[string]any{"provider": provider, "workspace": workspace}})
		return err
	})
}

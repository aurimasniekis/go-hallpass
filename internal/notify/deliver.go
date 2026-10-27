package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/outbox"
)

// Deliver implements outbox.Provider for chat messages. Content is rendered from the current request at delivery
// time; a request that is no longer pending is not announced. Failures never touch the request (HP-NTF-010).
func (svc *Service) Deliver(ctx context.Context, d outbox.Delivery) (outbox.Result, error) {
	switch d.Kind {
	case KindPending:
		var b pendingBody
		if err := json.Unmarshal(d.Body, &b); err != nil {
			return outbox.Result{}, fmt.Errorf("%w: bad body", outbox.ErrPermanent)
		}
		return svc.deliverPending(ctx, b)
	case KindUpdate:
		var b updateBody
		if err := json.Unmarshal(d.Body, &b); err != nil {
			return outbox.Result{}, fmt.Errorf("%w: bad body", outbox.ErrPermanent)
		}
		return svc.deliverUpdate(ctx, b)
	}
	return outbox.Result{}, fmt.Errorf("%w: unknown kind %q", outbox.ErrPermanent, d.Kind)
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if chat.IsPermanent(err) {
		return fmt.Errorf("%w: %w", outbox.ErrPermanent, err)
	}
	return err
}

func (svc *Service) deliverPending(ctx context.Context, b pendingBody) (outbox.Result, error) {
	r, err := svc.access.GetRequest(ctx, b.RequestID)
	if err != nil {
		return outbox.Result{}, fmt.Errorf("%w: request: %w", outbox.ErrPermanent, err)
	}
	if r.State != access.ReqPending {
		return outbox.Result{ProviderRef: ""}, nil // decided before delivery: nothing to announce
	}
	msg, err := svc.render(ctx, r, b.Actions, true)
	if err != nil {
		return outbox.Result{}, err
	}
	p, err := svc.provider(ctx, b.IntegrationID)
	if err != nil {
		return outbox.Result{}, fmt.Errorf("%w: integration: %w", outbox.ErrPermanent, err)
	}
	ref, err := p.Send(ctx, chat.Destination{ID: b.Destination}, msg)
	if err != nil {
		return outbox.Result{}, mapErr(err)
	}
	raw, _ := json.Marshal(ref)
	return outbox.Result{ProviderRef: string(raw)}, nil
}

// render builds the approval message: verified agent identity, server and role context, the untrusted reason,
// expiry, duration buttons, deny and a dashboard link — never addresses, usernames or credentials (HP-NTF-002/004).
func (svc *Service) render(ctx context.Context, r *access.Request, actions []chat.Action, validate bool) (chat.ApprovalMessage, error) {
	msg := chat.ApprovalMessage{RequestID: r.ID, RequestedDuration: r.RequestedDuration, ExpiresAt: r.ExpiresAt, Actions: actions,
		AgentSession: r.AgentSession}
	if svc.opts.PublicURL != "" {
		msg.DetailsURL = svc.opts.PublicURL + "/requests/" + r.ID
	}
	if a, err := svc.agents.Get(ctx, r.AgentID); err == nil {
		msg.AgentName, msg.AgentID = a.Name, a.ID
	}
	if keys, err := svc.agents.Keys(ctx, r.AgentID); err == nil {
		for _, k := range keys {
			if k.ID == r.AgentKeyID {
				msg.AgentKeyFingerprint = k.Fingerprint
			}
		}
	}
	if srv, err := svc.inventory.GetServer(ctx, r.ServerID); err == nil {
		msg.Server, msg.ServerDescription = srv.Alias, srv.Description
	}
	if role, err := svc.inventory.GetRole(ctx, r.RoleID); err == nil {
		msg.Role, msg.RoleDescription, msg.Capabilities = role.Alias, role.Description, role.Capabilities
	}
	if r.HasReason {
		reason, err := svc.access.Reason(ctx, r.ID)
		if err != nil {
			return msg, err
		}
		msg.Reason = reason
	}
	if !validate {
		return msg, nil // re-render context for an update (no buttons)
	}
	if err := msg.Validate(); err != nil {
		return msg, fmt.Errorf("%w: %w", outbox.ErrPermanent, err)
	}
	return msg, nil
}

// errOriginalPending makes the outbox retry an update until the original message has been delivered.
var errOriginalPending = errors.New("original approval message not delivered yet")

func (svc *Service) deliverUpdate(ctx context.Context, b updateBody) (outbox.Result, error) {
	orig, err := svc.s.R().GetOutboxRef(ctx, b.OriginalID)
	if err != nil {
		return outbox.Result{}, fmt.Errorf("%w: original message missing", outbox.ErrPermanent)
	}
	switch {
	case orig.State == "dead":
		return outbox.Result{}, fmt.Errorf("%w: original message was never delivered", outbox.ErrPermanent)
	case orig.State != "delivered":
		return outbox.Result{}, errOriginalPending
	case !orig.ProviderRef.Valid || orig.ProviderRef.String == "":
		return outbox.Result{}, nil // request was decided before the original went out
	}
	var ref chat.MessageRef
	if err := json.Unmarshal([]byte(orig.ProviderRef.String), &ref); err != nil {
		return outbox.Result{}, fmt.Errorf("%w: bad provider ref", outbox.ErrPermanent)
	}
	p, err := svc.provider(ctx, b.IntegrationID)
	if err != nil {
		return outbox.Result{}, fmt.Errorf("%w: integration: %w", outbox.ErrPermanent, err)
	}
	if err := p.Update(ctx, ref, b.Update); err != nil {
		return outbox.Result{}, mapErr(err)
	}
	return outbox.Result{ProviderRef: orig.ProviderRef.String}, nil
}

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

var _ = time.Second

package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/slack"
	"github.com/aurimasniekis/go-hallpass/internal/notify/telegram"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// SlackConfig is the non-secret Slack configuration.
type SlackConfig struct {
	TeamID  string `json:"team_id"`
	Command string `json:"command,omitempty"`
}

// TelegramConfig is the non-secret Telegram configuration.
type TelegramConfig struct {
	BotUsername string `json:"bot_username,omitempty"`
	// AllowedChatIDs are group chats besides route destinations that may interact (private chats are always
	// accepted for linking; decisions additionally require a linked approver).
	AllowedChatIDs []int64 `json:"allowed_chat_ids,omitempty"`
}

// Secret names per provider. Secrets are write-only (HP-OIDC-007 pattern, PLAN §10.4/§10.5).
var secretNames = map[string][]string{
	chat.ProviderSlack:    {"bot_token", "signing_secret"},
	chat.ProviderTelegram: {"bot_token", "webhook_secret"},
}

// Integration is a chat integration without secrets.
type Integration struct {
	ID          string          `json:"id"`
	Provider    string          `json:"provider"`
	Name        string          `json:"name"`
	Config      json.RawMessage `json:"config"`
	SecretsSet  []string        `json:"secrets_set"`
	Enabled     bool            `json:"enabled"`
	Version     int64           `json:"version"`
	WebhookPath string          `json:"webhook_path"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// IntegrationInput creates or updates an integration. Secrets: nil keeps stored values; a key with "" removes it.
type IntegrationInput struct {
	Version  int64             `json:"version"`
	Provider string            `json:"provider"`
	Name     *string           `json:"name"`
	Config   json.RawMessage   `json:"config"`
	Secrets  map[string]string `json:"secrets"`
	Enabled  *bool             `json:"enabled"`
}

func secretsAAD(id string) []byte { return keyring.FieldAAD("integrations", "secrets_enc", id) }

// WebhookPath is where the provider must deliver callbacks (HP-API-009: /hooks/*, no cookies).
func WebhookPath(provider, id string) string { return "/hooks/" + provider + "/" + id }

func (svc *Service) integration(r db.Integration) (*Integration, error) {
	sec, err := svc.secrets(r)
	if err != nil {
		return nil, err
	}
	var set []string
	for _, n := range secretNames[r.Provider] {
		if sec[n] != "" {
			set = append(set, n)
		}
	}
	if set == nil {
		set = []string{}
	}
	return &Integration{ID: r.ID, Provider: r.Provider, Name: r.Name, Config: json.RawMessage(r.ConfigJson), SecretsSet: set, Enabled: r.Enabled == 1,
		Version: r.Version, WebhookPath: WebhookPath(r.Provider, r.ID), CreatedAt: time.UnixMicro(r.CreatedAt).UTC(),
		UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC()}, nil
}

func (svc *Service) secrets(r db.Integration) (map[string]string, error) {
	pt, err := svc.kr.Open(keyring.PurposeCredential, secretsAAD(r.ID), r.SecretsEnc)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	return out, json.Unmarshal(pt, &out)
}

func validateConfig(provider string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	switch provider {
	case chat.ProviderSlack:
		var c SlackConfig
		if err := dec.Decode(&c); err != nil {
			return nil, invalid("invalid Slack config: %v", err)
		}
		if c.TeamID == "" || len(c.TeamID) > 32 {
			return nil, invalid("Slack config needs team_id")
		}
		out, _ := json.Marshal(c)
		return out, nil
	case chat.ProviderTelegram:
		var c TelegramConfig
		if err := dec.Decode(&c); err != nil {
			return nil, invalid("invalid Telegram config: %v", err)
		}
		if len(c.AllowedChatIDs) > 100 {
			return nil, invalid("too many allowed chats")
		}
		out, _ := json.Marshal(c)
		return out, nil
	}
	return nil, invalid("provider must be slack or telegram")
}

func validateSecrets(provider string, sec map[string]string) error {
	for k, v := range sec {
		if !slices.Contains(secretNames[provider], k) {
			return invalid("unknown secret %q", k)
		}
		if len(v) > 512 {
			return invalid("secret %q is too long", k)
		}
	}
	if provider == chat.ProviderTelegram {
		if t := sec["bot_token"]; t != "" {
			if _, err := telegram.BotIDFromToken(t); err != nil {
				return invalid("invalid Telegram bot token format")
			}
		}
		if w := sec["webhook_secret"]; w != "" && !telegram.ValidSecretToken(w) {
			return invalid("invalid Telegram webhook secret format")
		}
	}
	return nil
}

func (svc *Service) seal(id string, sec map[string]string) ([]byte, error) {
	b, _ := json.Marshal(sec)
	return svc.kr.Seal(keyring.PurposeCredential, secretsAAD(id), b)
}

// CreateIntegration adds a Slack or Telegram integration (integrations.manage + recent auth at the API).
// A Telegram webhook secret is generated when none is given.
func (svc *Service) CreateIntegration(ctx context.Context, actor audit.Actor, in IntegrationInput) (*Integration, error) {
	cfg, err := validateConfig(in.Provider, in.Config)
	if err != nil {
		return nil, err
	}
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" || len(*in.Name) > 64 {
		return nil, invalid("name is required (at most 64 bytes)")
	}
	sec := map[string]string{}
	for k, v := range in.Secrets {
		if v != "" {
			sec[k] = v
		}
	}
	if in.Provider == chat.ProviderTelegram && sec["webhook_secret"] == "" {
		if sec["webhook_secret"], err = telegram.GenerateSecretToken(); err != nil {
			return nil, err
		}
	}
	if err := validateSecrets(in.Provider, sec); err != nil {
		return nil, err
	}
	id := ids.New(ids.Integration)
	enc, err := svc.seal(id, sec)
	if err != nil {
		return nil, err
	}
	enabled := b2i(in.Enabled == nil || *in.Enabled)
	err = svc.s.W().TxNamed(ctx, "notify.create_integration", func(tx *store.Tx) error {
		if err := tx.Q.InsertIntegration(ctx, db.InsertIntegrationParams{ID: id, Provider: in.Provider, Name: strings.TrimSpace(*in.Name),
			ConfigJson: string(cfg), SecretsEnc: enc, Enabled: enabled, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "an integration with this name exists")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "integration.created", Target: audit.Target{Type: "integration", ID: id},
			Details: map[string]any{"provider": in.Provider, "name": *in.Name, "enabled": enabled}})
		return err
	})
	if err != nil {
		return nil, err
	}
	svc.registerWebhook(ctx, id)
	return svc.GetIntegration(ctx, id)
}

// registerWebhook points an enabled Telegram bot at Hallpass (setWebhook with the secret token). It is best effort:
// a failure is logged and the operator can retry by saving again or register the webhook manually.
func (svc *Service) registerWebhook(ctx context.Context, id string) {
	parts, err := svc.load(ctx, id)
	if err != nil || parts.row.Provider != chat.ProviderTelegram || parts.row.Enabled != 1 || svc.opts.PublicURL == "" {
		return
	}
	p, err := svc.provider(ctx, id)
	if err != nil {
		return
	}
	c, isTG := p.(*telegram.Client)
	if !isTG {
		return
	}
	hook := svc.opts.PublicURL + WebhookPath(chat.ProviderTelegram, id)
	if err := c.SetWebhook(ctx, hook, redact.NewSecret(parts.secrets["webhook_secret"]), false); err != nil {
		svc.log.Warn("telegram setWebhook failed; register the webhook manually or save the integration again", "integration_id", id, "error", err.Error())
	}
}

// UpdateIntegration changes an integration (optimistic concurrency on Version).
func (svc *Service) UpdateIntegration(ctx context.Context, actor audit.Actor, id string, in IntegrationInput) (*Integration, error) {
	cur, err := svc.s.R().GetIntegration(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "integration not found")
	} else if err != nil {
		return nil, err
	}
	cfg := json.RawMessage(cur.ConfigJson)
	if len(in.Config) > 0 {
		if cfg, err = validateConfig(cur.Provider, in.Config); err != nil {
			return nil, err
		}
	}
	name := cur.Name
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 64 {
			return nil, invalid("name is required (at most 64 bytes)")
		}
	}
	sec, err := svc.secrets(cur)
	if err != nil {
		return nil, err
	}
	changed := []string{}
	for k, v := range in.Secrets {
		changed = append(changed, k)
		if v == "" {
			delete(sec, k)
		} else {
			sec[k] = v
		}
	}
	if err := validateSecrets(cur.Provider, sec); err != nil {
		return nil, err
	}
	enc, err := svc.seal(id, sec)
	if err != nil {
		return nil, err
	}
	enabled := cur.Enabled == 1
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	enabledInt := b2i(enabled)
	err = svc.s.W().TxNamed(ctx, "notify.update_integration", func(tx *store.Tx) error {
		n, err := tx.Q.UpdateIntegration(ctx, db.UpdateIntegrationParams{Name: name, ConfigJson: string(cfg), SecretsEnc: enc, Enabled: enabledInt,
			UpdatedAt: tx.NowMicros(), ID: id, Version: in.Version})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "integration was modified concurrently; reload and retry")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "integration.updated", Target: audit.Target{Type: "integration", ID: id},
			Details: map[string]any{"enabled": enabled, "secrets_changed": changed}})
		return err
	})
	if err != nil {
		return nil, err
	}
	svc.forget(id)
	svc.registerWebhook(ctx, id)
	return svc.GetIntegration(ctx, id)
}

// DeleteIntegration removes an integration and its routes.
func (svc *Service) DeleteIntegration(ctx context.Context, actor audit.Actor, id string) error {
	err := svc.s.W().TxNamed(ctx, "notify.delete_integration", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteIntegration(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "integration not found")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "integration.deleted", Target: audit.Target{Type: "integration", ID: id}})
		return err
	})
	svc.forget(id)
	return err
}

// GetIntegration returns one integration.
func (svc *Service) GetIntegration(ctx context.Context, id string) (*Integration, error) {
	r, err := svc.s.R().GetIntegration(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "integration not found")
	} else if err != nil {
		return nil, err
	}
	return svc.integration(r)
}

// ListIntegrations returns all integrations.
func (svc *Service) ListIntegrations(ctx context.Context) ([]*Integration, error) {
	rows, err := svc.s.R().ListIntegrations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Integration, 0, len(rows))
	for _, r := range rows {
		i, err := svc.integration(r)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

// Route sends approval messages for matching targets to one destination (Slack channel ID, Telegram chat ID).
type Route struct {
	ID            string                `json:"id"`
	IntegrationID string                `json:"integration_id"`
	Provider      string                `json:"provider"`
	Destination   string                `json:"destination"`
	Targets       policy.TargetSelector `json:"targets"`
	Enabled       bool                  `json:"enabled"`
	CreatedAt     time.Time             `json:"created_at"`
}

// RouteInput creates a route.
type RouteInput struct {
	IntegrationID string                `json:"integration_id"`
	Destination   string                `json:"destination"`
	Targets       policy.TargetSelector `json:"targets"`
	Enabled       *bool                 `json:"enabled"`
}

// CreateRoute adds a notification route. An empty target selector matches nothing (PLAN §9).
func (svc *Service) CreateRoute(ctx context.Context, actor audit.Actor, in RouteInput) (*Route, error) {
	in.Destination = strings.TrimSpace(in.Destination)
	if in.Destination == "" || len(in.Destination) > 64 || strings.ContainsAny(in.Destination, " \t\r\n") {
		return nil, invalid("destination (channel or chat ID) is required")
	}
	targets, _ := json.Marshal(in.Targets)
	id := ids.New(ids.Route)
	enabled := b2i(in.Enabled == nil || *in.Enabled)
	err := svc.s.W().TxNamed(ctx, "notify.create_route", func(tx *store.Tx) error {
		if _, err := tx.Q.GetIntegration(ctx, in.IntegrationID); err != nil {
			return apperr.New(apperr.CodeNotFound, "integration not found")
		}
		if err := tx.Q.InsertRoute(ctx, db.InsertRouteParams{ID: id, IntegrationID: in.IntegrationID, Destination: in.Destination,
			TargetsJson: string(targets), Enabled: enabled, CreatedAt: tx.NowMicros()}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "this destination already has a route")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "notification_route.created", Target: audit.Target{Type: "notification_route", ID: id},
			Details: map[string]any{"integration_id": in.IntegrationID, "destination": in.Destination}})
		return err
	})
	if err != nil {
		return nil, err
	}
	r, err := svc.s.R().GetRoute(ctx, id)
	if err != nil {
		return nil, err
	}
	return routeFromRow(db.ListRoutesRow(r)), nil
}

// DeleteRoute removes a route.
func (svc *Service) DeleteRoute(ctx context.Context, actor audit.Actor, id string) error {
	return svc.s.W().TxNamed(ctx, "notify.delete_route", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteRoute(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "route not found")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "notification_route.deleted", Target: audit.Target{Type: "notification_route", ID: id}})
		return err
	})
}

func routeFromRow(r db.ListRoutesRow) *Route {
	var t policy.TargetSelector
	_ = json.Unmarshal([]byte(r.TargetsJson), &t)
	return &Route{ID: r.ID, IntegrationID: r.IntegrationID, Provider: r.Provider, Destination: r.Destination, Targets: t, Enabled: r.Enabled == 1,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC()}
}

// ListRoutes returns all routes.
func (svc *Service) ListRoutes(ctx context.Context) ([]*Route, error) {
	rows, err := svc.s.R().ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Route, len(rows))
	for i, r := range rows {
		out[i] = routeFromRow(r)
	}
	return out, nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ---- provider clients

func (svc *Service) forget(id string) {
	svc.mu.Lock()
	delete(svc.clients, id)
	svc.mu.Unlock()
}

type providerParts struct {
	row      db.Integration
	secrets  map[string]string
	slackCfg SlackConfig
	tgCfg    TelegramConfig
}

func (svc *Service) load(ctx context.Context, id string) (*providerParts, error) {
	r, err := svc.s.R().GetIntegration(ctx, id)
	if err != nil {
		return nil, err
	}
	sec, err := svc.secrets(r)
	if err != nil {
		return nil, err
	}
	p := &providerParts{row: r, secrets: sec}
	switch r.Provider {
	case chat.ProviderSlack:
		err = json.Unmarshal([]byte(r.ConfigJson), &p.slackCfg)
	case chat.ProviderTelegram:
		err = json.Unmarshal([]byte(r.ConfigJson), &p.tgCfg)
	}
	return p, err
}

// provider returns the outbound client for an integration (cached per version).
func (svc *Service) provider(ctx context.Context, id string) (chat.Provider, error) {
	parts, err := svc.load(ctx, id)
	if err != nil {
		return nil, err
	}
	svc.mu.Lock()
	c, found := svc.clients[id]
	svc.mu.Unlock()
	if found && c.version == parts.row.Version {
		return c.p, nil
	}
	var p chat.Provider
	switch parts.row.Provider {
	case chat.ProviderSlack:
		p, err = slack.NewClient(slack.ClientConfig{BotToken: redact.NewSecret(parts.secrets["bot_token"]), BaseURL: svc.opts.SlackBaseURL,
			ResponseURLBase: svc.opts.SlackResponseURLBase})
	case chat.ProviderTelegram:
		p, err = telegram.NewClient(telegram.ClientConfig{BotToken: redact.NewSecret(parts.secrets["bot_token"]), BaseURL: svc.opts.TelegramBaseURL})
	default:
		err = errors.New("unknown provider")
	}
	if err != nil {
		return nil, err
	}
	svc.mu.Lock()
	svc.clients[id] = cachedProvider{version: parts.row.Version, p: p}
	svc.mu.Unlock()
	return p, nil
}

// webhookHandler builds the inbound handler for an integration; verification happens inside the adapter before any
// parsing beyond size limits (HP-API-009, HP-NTF-005/006).
func (svc *Service) webhookHandler(ctx context.Context, provider, id string) (http.Handler, error) {
	parts, err := svc.load(ctx, id)
	if err != nil || parts.row.Provider != provider || parts.row.Enabled != 1 {
		return nil, apperr.New(apperr.CodeNotFound, "unknown integration")
	}
	switch provider {
	case chat.ProviderSlack:
		v, err := slack.NewVerifier(slack.VerifierConfig{SigningSecret: redact.NewSecret(parts.secrets["signing_secret"]),
			Replay: replayCache{svc: svc, provider: "slack:" + id}, Clock: svc.opts.Clock})
		if err != nil {
			return nil, err
		}
		var responder slack.Responder
		if p, err := svc.provider(ctx, id); err == nil {
			responder, _ = p.(slack.Responder)
		}
		return slack.NewHandler(slack.HandlerConfig{Verifier: v, Sink: sinkFor{svc: svc, integrationID: id}, TeamID: parts.slackCfg.TeamID,
			Command: parts.slackCfg.Command, ResponseURLBase: svc.opts.SlackResponseURLBase, Responder: responder, Clock: svc.opts.Clock, Logger: svc.log})
	case chat.ProviderTelegram:
		botID, err := telegram.BotIDFromToken(parts.secrets["bot_token"])
		if err != nil {
			return nil, err
		}
		allowed := allowlist{svc: svc, integrationID: id, extra: parts.tgCfg.AllowedChatIDs}
		wh, err := telegram.NewWebhook(telegram.WebhookConfig{SecretToken: redact.NewSecret(parts.secrets["webhook_secret"]), BotID: botID,
			BotUsername: parts.tgCfg.BotUsername, Allowlist: allowed, Replay: replayCache{svc: svc, provider: "telegram:" + id}, Clock: svc.opts.Clock})
		if err != nil {
			return nil, err
		}
		return telegram.NewHandler(telegram.HandlerConfig{Webhook: wh, Sink: sinkFor{svc: svc, integrationID: id}, Clock: svc.opts.Clock})
	}
	return nil, apperr.New(apperr.CodeNotFound, "unknown integration")
}

// allowlist accepts private chats (linking; decisions still need a linked approver), route destinations and the
// configured extra chats. Users are not pre-filtered: the core requires a provider link for every action.
type allowlist struct {
	svc           *Service
	integrationID string
	extra         []int64
}

func (a allowlist) ChatAllowed(ctx context.Context, chatID int64) (bool, error) {
	if chatID > 0 || slices.Contains(a.extra, chatID) {
		return true, nil
	}
	routes, err := a.svc.s.R().ListRoutes(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if r.IntegrationID == a.integrationID && r.Destination == formatInt(chatID) {
			return true, nil
		}
	}
	return false, nil
}

func (allowlist) UserAllowed(context.Context, int64) (bool, error) { return true, nil }

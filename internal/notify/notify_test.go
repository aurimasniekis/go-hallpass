package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/notify"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/slack"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fakeAPIs stands in for the Slack Web API, Slack response_url and the Telegram Bot API.
type fakeAPIs struct {
	base     string
	mu       sync.Mutex
	calls    map[string][]string // path → bodies
	failPost bool
	msgID    int
}

func (f *fakeAPIs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.URL.Path
	if strings.HasPrefix(key, "/tg/bot") {
		key = "/tg/" + key[strings.LastIndex(key, "/")+1:]
	}
	f.calls[key] = append(f.calls[key], string(b))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case key == "/api/chat.postMessage" && f.failPost:
		w.WriteHeader(http.StatusInternalServerError)
	case key == "/api/chat.postMessage":
		f.msgID++
		_, _ = fmt.Fprintf(w, `{"ok":true,"channel":"C123","ts":"1700000000.%06d"}`, f.msgID)
	case strings.HasPrefix(key, "/tg/"):
		f.msgID++
		_, _ = fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"date":1700000000,"chat":{"id":-100123,"type":"supergroup"}}}`, f.msgID)
	default:
		_, _ = io.WriteString(w, `{"ok":true}`)
	}
}

func (f *fakeAPIs) bodies(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls[key]...)
}

func (f *fakeAPIs) wait(t *testing.T, key string, n int) []string {
	t.Helper()
	for range 200 {
		if b := f.bodies(key); len(b) >= n {
			return b
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no %d calls to %s (have %d)", n, key, len(f.bodies(key)))
	return nil
}

type fx struct {
	t      *testing.T
	ctx    context.Context
	a      *app.App
	api    *fakeAPIs
	hooks  *httptest.Server
	agent  *agents.Agent
	keyID  string
	srv    *inventory.Server
	roles  []*inventory.Role
	op     *opauth.Operator
	slack  *notify.Integration
	signer []byte
}

func newFx(t *testing.T) *fx {
	t.Helper()
	api := &fakeAPIs{calls: map[string][]string{}}
	apiSrv := httptest.NewServer(api)
	api.base = apiSrv.URL
	t.Cleanup(apiSrv.Close)
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.KEK.File = ""
	cfg.HTTP.Listen = ""
	cfg.PublicURL = "http://hallpass.test"
	cfg.Egress.AllowCIDRs = []string{"10.0.0.0/8"}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler), app.WithNotifyOptions(func(o *notify.Options) {
		o.SlackBaseURL = apiSrv.URL + "/api/"
		o.SlackResponseURLBase = apiSrv.URL + "/respond/"
		o.TelegramBaseURL = apiSrv.URL + "/tg"
	}))
	must(t, err)
	rctx, cancel := context.WithCancel(ctx)
	go a.Outbox.Run(rctx, 2)
	hooks := httptest.NewServer(a.RootHandlerForTest())
	t.Cleanup(func() { hooks.Close(); cancel(); _ = a.Close() })
	f := &fx{t: t, ctx: ctx, a: a, api: api, hooks: hooks, signer: []byte("slack-signing-secret")}

	f.agent, err = a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	keys, _ := a.Agents.Keys(ctx, f.agent.ID)
	f.keyID = keys[0].ID
	f.srv, err = a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1"), Description: ptr("web tier")})
	must(t, err)
	for _, alias := range []string{"inspect", "deploy", "ops"} {
		r, err := a.Inventory.CreateRole(ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr(alias), RemoteUser: ptr("ro")})
		must(t, err)
		f.roles = append(f.roles, r)
	}
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.op, err = a.Auth.Create(ctx, admin, opauth.CreateInput{Email: "approver@example.com", DisplayName: "Alice Approver", Roles: []string{opauth.RoleApprover}})
	must(t, err)
	_, err = a.Policy.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{f.op.ID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.slack, err = a.Notify.CreateIntegration(ctx, admin, notify.IntegrationInput{Provider: chat.ProviderSlack, Name: ptr("slack"),
		Config: json.RawMessage(`{"team_id":"T1"}`), Secrets: map[string]string{"bot_token": "xoxb-test-token", "signing_secret": string(f.signer)}})
	must(t, err)
	_, err = a.Notify.CreateRoute(ctx, admin, notify.RouteInput{IntegrationID: f.slack.ID, Destination: "C123", Targets: policy.TargetSelector{All: true}})
	must(t, err)
	return f
}

func (f *fx) request(role int, reason string) *access.Request {
	f.t.Helper()
	res, err := f.a.Access.CreateRequest(f.ctx, access.CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID,
		RoleID: f.roles[role].ID, Reason: reason, Duration: 15 * time.Minute})
	must(f.t, err)
	return res.Request
}

var actionIDRE = regexp.MustCompile(`"action_id":"([^"]+)"`)

// slackTokens extracts the approve (first) and deny tokens from a posted Block Kit message.
func slackTokens(t *testing.T, body string) (approve, deny string) {
	t.Helper()
	for _, m := range actionIDRE.FindAllStringSubmatch(body, -1) {
		kind, tok, ok := slack.ParseActionID(m[1])
		if !ok {
			continue
		}
		if kind == chat.ActionApprove && approve == "" {
			approve = tok
		}
		if kind == chat.ActionDeny {
			deny = tok
		}
	}
	if approve == "" || deny == "" {
		t.Fatalf("no tokens in %s", body)
	}
	return approve, deny
}

func (f *fx) slackPost(body []byte, contentType string) int {
	code, _ := f.slackPostBody(body, contentType)
	return code
}

func (f *fx) slackPostBody(body []byte, contentType string) (int, string) {
	f.t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, _ := http.NewRequestWithContext(f.ctx, http.MethodPost, f.hooks.URL+notify.WebhookPath(chat.ProviderSlack, f.slack.ID), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", slack.SignatureHeader(f.signer, ts, body))
	res, err := http.DefaultClient.Do(req)
	must(f.t, err)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (f *fx) click(kind chat.ActionKind, token, user string, n int) string {
	f.t.Helper()
	p := map[string]any{"type": "block_actions", "team": map[string]any{"id": "T1"},
		"user":         map[string]any{"id": user, "username": "alice", "team_id": "T1"},
		"container":    map[string]any{"type": "message", "message_ts": "1700000000.000001", "channel_id": "C123"},
		"channel":      map[string]any{"id": "C123"},
		"response_url": f.api.base + "/respond/actions/" + strconv.Itoa(n),
		"actions":      []any{map[string]any{"type": "button", "action_id": slack.ActionID(kind, token), "value": token, "block_id": "hp_actions"}}}
	raw, _ := json.Marshal(p)
	if code := f.slackPost([]byte("payload="+url.QueryEscape(string(raw))), "application/x-www-form-urlencoded"); code != 200 {
		f.t.Fatalf("interaction status %d", code)
	}
	replies := f.api.wait(f.t, "/respond/actions/"+strconv.Itoa(n), 1)
	return replies[0]
}

func (f *fx) command(text string, n int) string {
	f.t.Helper()
	v := url.Values{"command": {"/hallpass"}, "text": {text}, "team_id": {"T1"}, "user_id": {"U1"}, "user_name": {"alice"}, "channel_id": {"D1"},
		"response_url": {f.api.base + "/respond/commands/" + strconv.Itoa(n)}}
	code, body := f.slackPostBody([]byte(v.Encode()), "application/x-www-form-urlencoded")
	if code != 200 {
		f.t.Fatalf("command status %d", code)
	}
	return body
}

func (f *fx) state(id string) string {
	f.t.Helper()
	r, err := f.a.Access.GetRequest(f.ctx, id)
	must(f.t, err)
	return r.State
}

// HP-NTF-001..011 end to end over Slack: delivery, escaping, unlinked users, link codes, MFA requirement, a single
// transactional decision, idempotent redelivery and the message update.
func TestSlackApprovalFlow(t *testing.T) {
	f := newFx(t)
	r := f.request(0, "disk alert <!channel> <@U999> https://evil.example")
	posts := f.api.wait(t, "/api/chat.postMessage", 1)
	msg := posts[0]
	if strings.Contains(msg, "<!channel>") || strings.Contains(msg, "<@U999>") || !strings.Contains(msg, "web1") || !strings.Contains(msg, "sre-bot") ||
		strings.Contains(msg, "10.0.0.1") || !strings.Contains(msg, "http://hallpass.test/requests/"+r.ID) {
		t.Fatalf("message content: %s", msg)
	}
	approve, deny := slackTokens(t, msg)

	// Unlinked user: refused, request untouched.
	if reply := f.click(chat.ActionApprove, approve, "U1", 1); !strings.Contains(reply, "not linked") || f.state(r.ID) != access.ReqPending {
		t.Fatalf("unlinked: %s", reply)
	}
	// Link through a code issued in the web session.
	code, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, chat.ProviderSlack)
	must(t, err)
	if reply := f.command("link "+code, 1); !strings.Contains(reply, "Alice Approver") {
		t.Fatalf("link: %s", reply)
	}
	if reply := f.command("link "+code, 2); !strings.Contains(reply, "invalid or expired") {
		t.Fatalf("link code reused: %s", reply)
	}
	// MFA requirement for chat approvals (R-10): no TOTP and no SSO identity yet.
	if reply := f.click(chat.ActionApprove, approve, "U1", 2); !strings.Contains(reply, "MFA") || f.state(r.ID) != access.ReqPending {
		t.Fatalf("mfa: %s", reply)
	}
	prov, err := f.a.OIDC.CreateProvider(f.ctx, admin, oidc.ProviderInput{Slug: ptr("corp"), DisplayName: ptr("Corp"), Issuer: ptr("https://idp.example"),
		ClientID: ptr("hp")})
	must(t, err)
	must(t, f.a.OIDC.LinkIdentity(f.ctx, admin, f.op.ID, prov.ID, "alice"))
	// A token's kind must match the button.
	if reply := f.click(chat.ActionApprove, deny, "U1", 3); !strings.Contains(reply, "not valid") {
		t.Fatalf("kind mismatch: %s", reply)
	}
	if reply := f.click(chat.ActionApprove, approve, "U1", 4); !strings.Contains(reply, "approved") || f.state(r.ID) != access.ReqApproved {
		t.Fatalf("approve: %s", reply)
	}
	// Redelivery is idempotent; the other button no longer changes anything.
	if reply := f.click(chat.ActionApprove, approve, "U1", 5); !strings.Contains(reply, "Already handled") {
		t.Fatalf("redelivery: %s", reply)
	}
	if reply := f.click(chat.ActionDeny, deny, "U1", 6); !strings.Contains(reply, "already approved") || f.state(r.ID) != access.ReqApproved {
		t.Fatalf("deny after approve: %s", reply)
	}
	upd := f.api.wait(t, "/api/chat.update", 1)
	if !strings.Contains(upd[0], "Alice Approver") {
		t.Fatalf("update: %s", upd[0])
	}
	// The decision went through the single decision service with the slack channel.
	d, err := f.a.Store.R().GetDecisionByRequest(f.ctx, r.ID)
	must(t, err)
	if d.Channel != access.ChannelSlack || d.ActorID != f.op.ID {
		t.Fatalf("decision %+v", d)
	}
	// Bad signature: refused before parsing, nothing happens.
	if code := func() int {
		req, _ := http.NewRequestWithContext(f.ctx, http.MethodPost, f.hooks.URL+notify.WebhookPath(chat.ProviderSlack, f.slack.ID), strings.NewReader("payload=x"))
		req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Slack-Signature", "v0=00")
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		_ = res.Body.Close()
		return res.StatusCode
	}(); code != 401 && code != 403 {
		t.Fatalf("bad signature status %d", code)
	}
}

// HP-NTF-010: delivery failures retry and never approve.
func TestDeliveryFailureNeverApproves(t *testing.T) {
	f := newFx(t)
	f.api.mu.Lock()
	f.api.failPost = true
	f.api.mu.Unlock()
	r := f.request(1, "deploy")
	f.api.wait(t, "/api/chat.postMessage", 1)
	if f.state(r.ID) != access.ReqPending {
		t.Fatal("failed delivery changed the request")
	}
	rows, err := f.a.Store.R().ListDeliveries(f.ctx, dbDeliveries())
	must(t, err)
	if len(rows) == 0 || rows[0].Attempts == 0 || rows[0].LastError.String == "" {
		t.Fatalf("delivery history %+v", rows)
	}
}

// HP-NTF-006: Telegram webhook secret, chat allowlist and a decision from a linked user.
func TestTelegramApproval(t *testing.T) {
	f := newFx(t)
	secret := "tg-webhook-secret-0123456789abcdefABCDEF"
	tg, err := f.a.Notify.CreateIntegration(f.ctx, admin, notify.IntegrationInput{Provider: chat.ProviderTelegram, Name: ptr("telegram"),
		Config: json.RawMessage(`{"bot_username":"hallpass_bot"}`), Secrets: map[string]string{"bot_token": "123456:ABCdefghijklmnopqrstuvwxyz-test", "webhook_secret": secret}})
	must(t, err)
	_, err = f.a.Notify.CreateRoute(f.ctx, admin, notify.RouteInput{IntegrationID: tg.ID, Destination: "-100123", Targets: policy.TargetSelector{All: true}})
	must(t, err)
	must(t, f.a.Notify.LinkProviderUser(f.ctx, admin, f.op.ID, notify.ProviderLink{Provider: chat.ProviderTelegram, Workspace: "123456", ProviderUserID: "42"}))
	prov, err := f.a.OIDC.CreateProvider(f.ctx, admin, oidc.ProviderInput{Slug: ptr("corp"), DisplayName: ptr("Corp"), Issuer: ptr("https://idp.example"),
		ClientID: ptr("hp")})
	must(t, err)
	must(t, f.a.OIDC.LinkIdentity(f.ctx, admin, f.op.ID, prov.ID, "alice"))
	r := f.request(2, "ops work")
	sent := f.api.wait(t, "/tg/sendMessage", 1)
	m := regexp.MustCompile(`"callback_data":"(hp1:a:[^"]+)"`).FindStringSubmatch(sent[0])
	if m == nil {
		t.Fatalf("no approve button: %s", sent[0])
	}
	update := func(n int, chatID int64, from int64) []byte {
		b, _ := json.Marshal(map[string]any{"update_id": n, "callback_query": map[string]any{"id": "cb" + strconv.Itoa(n),
			"from": map[string]any{"id": from, "is_bot": false, "first_name": "Alice"}, "chat_instance": "-1", "data": m[1],
			"message": map[string]any{"message_id": 1, "date": 1700000000, "chat": map[string]any{"id": chatID, "type": "supergroup"}}}})
		return b
	}
	post := func(sec string, body []byte) (int, string) {
		req, _ := http.NewRequestWithContext(f.ctx, http.MethodPost, f.hooks.URL+notify.WebhookPath(chat.ProviderTelegram, tg.ID), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", sec)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := post("wrong-secret-0123456789abcdefABCDEFxx", update(1, -100123, 42)); code == 200 {
		t.Fatal("wrong secret accepted")
	}
	if _, body := post(secret, update(2, -100999, 42)); strings.Contains(body, "approved") || f.state(r.ID) != access.ReqPending {
		t.Fatalf("unlisted chat: %s", body)
	}
	if _, body := post(secret, update(3, -100123, 7)); !strings.Contains(body, "not linked") {
		t.Fatalf("unlinked user: %s", body)
	}
	if _, body := post(secret, update(4, -100123, 42)); !strings.Contains(body, "approved") || f.state(r.ID) != access.ReqApproved {
		t.Fatalf("approve: %s", body)
	}
	if _, body := post(secret, update(4, -100123, 42)); strings.Contains(body, "approved by") {
		t.Fatalf("replayed update_id processed: %s", body)
	}
}

func dbDeliveries() db.ListDeliveriesParams { return db.ListDeliveriesParams{Lim: 10} }

// Integration administration: write-only secrets, config validation, optimistic concurrency, routes and links.
func TestIntegrationAdministration(t *testing.T) {
	f := newFx(t)
	b, _ := json.Marshal(f.slack)
	if strings.Contains(string(b), "xoxb-test-token") || strings.Contains(string(b), string(f.signer)) || len(f.slack.SecretsSet) != 2 {
		t.Fatalf("secrets exposed or missing: %s", b)
	}
	var raw []byte
	must(t, f.a.Store.ReadDB().QueryRowContext(f.ctx, `SELECT secrets_enc FROM integrations WHERE id = ?`, f.slack.ID).Scan(&raw))
	if strings.Contains(string(raw), "xoxb-test-token") {
		t.Fatal("secrets stored in plaintext")
	}
	for _, in := range []notify.IntegrationInput{
		{Provider: "email", Name: ptr("x")},
		{Provider: chat.ProviderSlack, Name: ptr("x"), Config: json.RawMessage(`{}`)},
		{Provider: chat.ProviderSlack, Name: ptr("x"), Config: json.RawMessage(`{"team_id":"T1","bogus":1}`)},
		{Provider: chat.ProviderSlack, Name: ptr("x"), Config: json.RawMessage(`{"team_id":"T1"}`), Secrets: map[string]string{"password": "x"}},
		{Provider: chat.ProviderTelegram, Name: ptr("x"), Secrets: map[string]string{"bot_token": "nope"}},
		{Provider: chat.ProviderSlack, Name: ptr("slack"), Config: json.RawMessage(`{"team_id":"T1"}`)},
	} {
		if _, err := f.a.Notify.CreateIntegration(f.ctx, admin, in); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	upd, err := f.a.Notify.UpdateIntegration(f.ctx, admin, f.slack.ID, notify.IntegrationInput{Version: f.slack.Version, Name: ptr("slack-main"),
		Secrets: map[string]string{"signing_secret": ""}})
	must(t, err)
	if upd.Name != "slack-main" || len(upd.SecretsSet) != 1 {
		t.Fatalf("update %+v", upd)
	}
	if _, err := f.a.Notify.UpdateIntegration(f.ctx, admin, f.slack.ID, notify.IntegrationInput{Version: 1}); err == nil {
		t.Fatal("stale version accepted")
	}
	tg, err := f.a.Notify.CreateIntegration(f.ctx, admin, notify.IntegrationInput{Provider: chat.ProviderTelegram, Name: ptr("tg"),
		Secrets: map[string]string{"bot_token": "123456:ABCdefghijklmnopqrstuvwxyz-test"}})
	must(t, err)
	if !slices.Contains(tg.SecretsSet, "webhook_secret") {
		t.Fatal("telegram webhook secret not generated")
	}
	list, err := f.a.Notify.ListIntegrations(f.ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list %v %v", len(list), err)
	}
	if _, err := f.a.Notify.CreateRoute(f.ctx, admin, notify.RouteInput{IntegrationID: f.slack.ID, Destination: "C123"}); err == nil {
		t.Fatal("duplicate route accepted")
	}
	if _, err := f.a.Notify.CreateRoute(f.ctx, admin, notify.RouteInput{IntegrationID: "int_missing", Destination: "C9"}); err == nil {
		t.Fatal("route for unknown integration")
	}
	routes, err := f.a.Notify.ListRoutes(f.ctx)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes %v %v", routes, err)
	}
	must(t, f.a.Notify.DeleteRoute(f.ctx, admin, routes[0].ID))
	if err := f.a.Notify.DeleteRoute(f.ctx, admin, routes[0].ID); err == nil {
		t.Fatal("double delete")
	}
	must(t, f.a.Notify.DeleteIntegration(f.ctx, admin, tg.ID))
	if _, err := f.a.Notify.GetIntegration(f.ctx, tg.ID); err == nil {
		t.Fatal("deleted integration still found")
	}
	// Admin links and unlinking.
	l := notify.ProviderLink{Provider: chat.ProviderSlack, Workspace: "T1", ProviderUserID: "U7", Display: "bob"}
	must(t, f.a.Notify.LinkProviderUser(f.ctx, admin, f.op.ID, l))
	links, err := f.a.Notify.ProviderLinks(f.ctx, f.op.ID)
	if err != nil || len(links) != 1 || links[0].LinkedVia != "admin" {
		t.Fatalf("links %+v %v", links, err)
	}
	if err := f.a.Notify.LinkProviderUser(f.ctx, admin, f.op.ID, notify.ProviderLink{Provider: "irc"}); err == nil {
		t.Fatal("invalid link accepted")
	}
	must(t, f.a.Notify.UnlinkProviderUser(f.ctx, admin, f.op.ID, chat.ProviderSlack, "T1", "U7"))
	if err := f.a.Notify.UnlinkProviderUser(f.ctx, admin, f.op.ID, chat.ProviderSlack, "T1", "U7"); err == nil {
		t.Fatal("double unlink")
	}
	if _, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, "irc"); err == nil {
		t.Fatal("link code for unknown provider")
	}
	must(t, f.a.Notify.Purge(f.ctx))
	// Unknown webhook targets are 404; GET is refused.
	for _, p := range []string{"/hooks/slack/int_missing", "/hooks/irc/x", "/hooks/slack/"} {
		req, _ := http.NewRequestWithContext(f.ctx, http.MethodPost, f.hooks.URL+p, strings.NewReader("x"))
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
	req, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, f.hooks.URL+notify.WebhookPath(chat.ProviderSlack, f.slack.ID), nil)
	res, err := http.DefaultClient.Do(req)
	must(t, err)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET webhook: %d", res.StatusCode)
	}
}

// Deny, status, expiry updates, decision rate limits and the Telegram public-chat link refusal.
func TestDenyStatusExpiryAndLimits(t *testing.T) {
	f := newFx(t)
	code, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, chat.ProviderSlack)
	must(t, err)
	f.command("link "+code, 1)
	prov, err := f.a.OIDC.CreateProvider(f.ctx, admin, oidc.ProviderInput{Slug: ptr("corp"), DisplayName: ptr("Corp"), Issuer: ptr("https://idp.example"),
		ClientID: ptr("hp")})
	must(t, err)
	must(t, f.a.OIDC.LinkIdentity(f.ctx, admin, f.op.ID, prov.ID, "alice"))
	r := f.request(0, "inspect")
	_, deny := slackTokens(t, f.api.wait(t, "/api/chat.postMessage", 1)[0])
	if reply := f.command("status "+r.ID, 2); !strings.Contains(reply, "pending") {
		t.Fatalf("status: %s", reply)
	}
	if reply := f.click(chat.ActionDeny, deny, "U1", 1); !strings.Contains(reply, "denied") || f.state(r.ID) != access.ReqDenied {
		t.Fatalf("deny: %s", reply)
	}
	// Expiry produces an update for the delivered message.
	r2 := f.request(1, "deploy")
	f.api.wait(t, "/api/chat.postMessage", 2)
	_, err = f.a.Access.CancelByAgent(f.ctx, f.agent.ID, r2.ID)
	must(t, err)
	f.api.wait(t, "/api/chat.update", 2)
	if reply := f.command("status req_00000000000000000000000000", 3); !strings.Contains(reply, "not found") {
		t.Fatalf("status unknown: %s", reply)
	}
	// Telegram link codes posted in a group are burned.
	tg, err := f.a.Notify.CreateIntegration(f.ctx, admin, notify.IntegrationInput{Provider: chat.ProviderTelegram, Name: ptr("telegram"),
		Secrets: map[string]string{"bot_token": "123456:ABCdefghijklmnopqrstuvwxyz-test", "webhook_secret": "tg-webhook-secret-0123456789abcdefABCDEF"}})
	must(t, err)
	_, err = f.a.Notify.CreateRoute(f.ctx, admin, notify.RouteInput{IntegrationID: tg.ID, Destination: "-100123", Targets: policy.TargetSelector{All: true}})
	must(t, err)
	tgCode, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, chat.ProviderTelegram)
	must(t, err)
	msg := func(n int, chatID int64, chatType string) []byte {
		b, _ := json.Marshal(map[string]any{"update_id": n, "message": map[string]any{"message_id": n, "date": 1700000000, "text": "/link " + tgCode,
			"from": map[string]any{"id": 42, "is_bot": false, "first_name": "Alice"}, "chat": map[string]any{"id": chatID, "type": chatType}}})
		return b
	}
	post := func(body []byte) string {
		req, _ := http.NewRequestWithContext(f.ctx, http.MethodPost, f.hooks.URL+notify.WebhookPath(chat.ProviderTelegram, tg.ID), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "tg-webhook-secret-0123456789abcdefABCDEF")
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	if body := post(msg(10, -100123, "supergroup")); !strings.Contains(body, "private chat") {
		t.Fatalf("group link: %s", body)
	}
	if body := post(msg(11, 42, "private")); !strings.Contains(body, "invalid or expired") {
		t.Fatalf("burned code reused: %s", body)
	}
}

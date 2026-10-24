package notify_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/notify"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

func (f *fx) linkSlack(user string) {
	f.t.Helper()
	must(f.t, f.a.Notify.LinkProviderUser(f.ctx, admin, f.op.ID, notify.ProviderLink{Provider: chat.ProviderSlack, Workspace: "T1", ProviderUserID: user}))
}

func (f *fx) links() int {
	f.t.Helper()
	l, err := f.a.Notify.ProviderLinks(f.ctx, f.op.ID)
	must(f.t, err)
	return len(l)
}

// SR-10 (HP-NTF-011, T-11): disabling an operator removes its chat links (and unused link codes) for good:
// re-enabling does not restore chat approval power.
func TestChatLinksRevokedOnDisable(t *testing.T) {
	f := newFx(t)
	_, err := f.a.Auth.Create(f.ctx, admin, opauth.CreateInput{Email: "root@example.com", DisplayName: "Root", Roles: []string{opauth.RoleAdministrator}})
	must(t, err)
	f.linkSlack("U1")
	if _, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, chat.ProviderTelegram); err != nil {
		t.Fatal(err)
	}
	if f.links() != 1 {
		t.Fatal("link not created")
	}
	_, err = f.a.Auth.SetEnabled(f.ctx, admin, f.op.ID, false)
	must(t, err)
	_, err = f.a.Auth.SetEnabled(f.ctx, admin, f.op.ID, true)
	must(t, err)
	if n := f.links(); n != 0 {
		t.Fatalf("%d chat links survived disabling the operator", n)
	}
	var codes int
	must(t, f.a.Store.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM provider_link_codes WHERE operator_id = ? AND used_at IS NULL`, f.op.ID).Scan(&codes))
	if codes != 0 {
		t.Fatalf("%d unused link codes survived disabling the operator", codes)
	}
}

// SR-10: a password reset (first password or a later reset) removes the operator's chat links.
func TestChatLinksRevokedOnPasswordReset(t *testing.T) {
	f := newFx(t)
	for i, pw := range []string{"first password for alice", "second password for alice"} {
		f.linkSlack("U1")
		tok, _, err := f.a.Auth.IssueResetToken(f.ctx, admin, f.op.ID)
		must(t, err)
		must(t, f.a.Auth.ResetPassword(f.ctx, tok, pw))
		if n := f.links(); n != 0 {
			t.Fatalf("reset %d: %d chat links survived the password reset", i+1, n)
		}
	}
}

func (f *fx) auditCount(action, reason string) int {
	f.t.Helper()
	var n int
	must(f.t, f.a.Store.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = ? AND json_extract(details_json, '$.reason') = ?`,
		action, reason).Scan(&n))
	return n
}

// SR-40 (HP-NTF-012, PLAN §10.7): one provider user gets at most 5 actions per second.
func TestPerProviderUserLimit(t *testing.T) {
	f := newFx(t)
	limited := 0
	for i := range notify.UserActionsPerSecond + 3 {
		if reply := f.click(chat.ActionApprove, "AAAAAAAAAAAAAAAAAAAAAA", "U9", 100+i); strings.Contains(reply, "Too many actions") {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a provider user exceeded 5 actions per second without being limited")
	}
	if f.auditCount("chat.action.refused", "rate_limited") == 0 {
		t.Fatal("rate-limited chat actions not audited")
	}
}

// SR-41 (PLAN §10.5): refused chat actions and failed link attempts leave a (rate-limited) audit trail.
func TestRefusedChatActionsAudited(t *testing.T) {
	f := newFx(t)
	r := f.request(0, "deploy")
	approve, _ := slackTokens(t, f.api.wait(t, "/api/chat.postMessage", 1)[0])
	if reply := f.click(chat.ActionApprove, approve, "U1", 1); !strings.Contains(reply, "not linked") || f.state(r.ID) != access.ReqPending {
		t.Fatalf("unlinked: %s", reply)
	}
	if f.auditCount("chat.action.refused", "not_linked") != 1 {
		t.Fatal("unlinked click not audited")
	}
	for i := range 4 { // a guessing attempt: audited, at most 3 rows per minute
		if reply := f.command("link ABCDEFGH", 10+i); !strings.Contains(reply, "invalid or expired") {
			t.Fatalf("wrong code: %s", reply)
		}
	}
	if n := f.auditCount("provider_link.failed", "invalid_or_expired_code"); n == 0 || n > 3 {
		t.Fatalf("%d provider_link.failed rows", n)
	}
}

// SR-19 (HP-NTF-012): a flood of random integration IDs from many sources does not push a real integration into
// the limiter's shared overflow window, and one source is limited on its own.
func TestWebhookLimiterIgnoresUnknownIDs(t *testing.T) {
	f := newFx(t)
	h := f.a.Notify.WebhookHandler()
	post := func(path, src string) int {
		req := httptest.NewRequestWithContext(f.ctx, http.MethodPost, path, strings.NewReader("{}"))
		req.RemoteAddr = src
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	for i := range 5000 {
		post(fmt.Sprintf("/hooks/slack/int_bogus%05d", i), fmt.Sprintf("10.%d.%d.%d:4000", i>>16&255, i>>8&255, i&255))
	}
	if code := post(notify.WebhookPath(chat.ProviderSlack, f.slack.ID), "192.0.2.10:4000"); code == http.StatusTooManyRequests || code == http.StatusNotFound {
		t.Fatalf("real integration refused after a random-ID flood: %d", code)
	}
	limited := false
	for range notify.WebhookPerSource + 1 {
		if post("/hooks/slack/int_other", "198.51.100.7:4000") == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("one source is not rate limited")
	}
}

// SR-36 (HP-CRY-002): a link code issued before a token-key rotation still links afterwards, and an action token
// still decides (lookups MAC under every non-retired token key).
func TestTokenKeyRotationKeepsOutstandingCodes(t *testing.T) {
	f := newFx(t)
	r := f.request(0, "deploy")
	_, deny := slackTokens(t, f.api.wait(t, "/api/chat.postMessage", 1)[0])
	code, _, err := f.a.Notify.IssueLinkCode(f.ctx, f.op.ID, chat.ProviderSlack)
	must(t, err)
	if _, err := f.a.Keyring.Rotate(f.ctx, f.a.Store, keyring.PurposeToken); err != nil {
		t.Fatal(err)
	}
	if reply := f.command("link "+code, 1); !strings.Contains(reply, "Alice Approver") {
		t.Fatalf("link after rotation: %s", reply)
	}
	if reply := f.click(chat.ActionDeny, deny, "U1", 2); strings.Contains(reply, "not valid") {
		t.Fatalf("action token after rotation: %s", reply)
	}
	_ = r
}

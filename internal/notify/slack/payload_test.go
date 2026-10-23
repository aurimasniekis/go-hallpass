package slack

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

const testTeam = "T0HALLPASS"

var parseOpts = ParseOptions{TeamID: testTeam, Now: time.Unix(1_700_000_000, 0)}

func interaction(mut func(p map[string]any)) map[string]any {
	p := map[string]any{
		"type": "block_actions",
		"team": map[string]any{"id": testTeam, "domain": "acme"},
		"user": map[string]any{"id": "U123ABC", "username": "alice", "name": "alice", "team_id": testTeam},
		"container": map[string]any{
			"type": "message", "message_ts": "1700000000.000100", "channel_id": "C0APPROVE", "is_ephemeral": false,
		},
		"channel":      map[string]any{"id": "C0APPROVE", "name": "approvals"},
		"response_url": "https://hooks.slack.com/actions/T0HALLPASS/1/abc",
		"trigger_id":   "1.2.3",
		"actions": []any{map[string]any{
			"type": "button", "action_id": ActionID(chat.ActionApprove, chattest.Token(2)), "value": chattest.Token(2),
			"block_id": "hp_actions", "action_ts": "1700000001.1",
		}},
	}
	if mut != nil {
		mut(p)
	}
	return p
}

func formBody(p map[string]any) []byte {
	raw, _ := json.Marshal(p)
	return []byte("payload=" + url.QueryEscape(string(raw)))
}

func TestParseInteraction(t *testing.T) {
	in, err := ParseBody(formBody(interaction(nil)), parseOpts)
	if err != nil {
		t.Fatal(err)
	}
	if in.Event == nil || in.Event.Kind != chat.EventInteraction || in.IsCommand {
		t.Fatalf("event %+v", in)
	}
	ia := in.Event.Interaction
	want := chat.Interaction{
		Identity:      chat.Identity{Provider: chat.ProviderSlack, Workspace: testTeam, UserID: "U123ABC", UserName: "alice", ChatID: "C0APPROVE"},
		ActionTokenID: chattest.Token(2), Kind: chat.ActionApprove,
		Message:    chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0APPROVE", MessageID: "1700000000.000100"},
		ReceivedAt: parseOpts.Now,
	}
	if *ia != want {
		t.Fatalf("got %+v\nwant %+v", *ia, want)
	}
	if in.ResponseURL != "https://hooks.slack.com/actions/T0HALLPASS/1/abc" {
		t.Fatalf("response url %q", in.ResponseURL)
	}
}

func TestParseInteractionVariants(t *testing.T) {
	// Deny, DM channel, display name fallback, hostile name, no channel object.
	in, err := ParseBody(formBody(interaction(func(p map[string]any) {
		p["actions"] = []any{map[string]any{"type": "button", "action_id": ActionID(chat.ActionDeny, chattest.Token(4)), "value": chattest.Token(4)}}
		p["user"] = map[string]any{"id": "W123", "name": "<!channel>\u202e evil"}
		p["container"] = map[string]any{"type": "message", "message_ts": "1.2", "channel_id": "D0DM"}
		delete(p, "channel")
		p["response_url"] = "https://evil.example/actions/x"
	})), parseOpts)
	if err != nil {
		t.Fatal(err)
	}
	ia := in.Event.Interaction
	if ia.Kind != chat.ActionDeny || !ia.PrivateChat || ia.UserName != "<!channel> evil" || in.ResponseURL != "" {
		t.Fatalf("%+v %q", ia, in.ResponseURL)
	}
	// Ephemeral or unknown container: no message ref.
	in, err = ParseBody(formBody(interaction(func(p map[string]any) {
		p["container"] = map[string]any{"type": "view"}
	})), parseOpts)
	if err != nil || in.Event.Interaction.Message != (chat.MessageRef{}) {
		t.Fatalf("container %v %+v", err, in.Event)
	}
}

func TestParseInteractionRejections(t *testing.T) {
	cases := map[string]struct {
		mut  func(p map[string]any)
		want chat.RejectReason
	}{
		"wrong team":    {func(p map[string]any) { p["team"] = map[string]any{"id": "T0OTHER"} }, chat.RejectWorkspace},
		"missing team":  {func(p map[string]any) { delete(p, "team") }, chat.RejectMalformed},
		"bad user id":   {func(p map[string]any) { p["user"] = map[string]any{"id": "u-lower"} }, chat.RejectMalformed},
		"view submit":   {func(p map[string]any) { p["type"] = "view_submission" }, chat.RejectUnsupported},
		"no actions":    {func(p map[string]any) { p["actions"] = []any{} }, chat.RejectMalformed},
		"two actions":   {func(p map[string]any) { p["actions"] = []any{p["actions"].([]any)[0], p["actions"].([]any)[0]} }, chat.RejectMalformed},
		"select menu":   {func(p map[string]any) { p["actions"].([]any)[0].(map[string]any)["type"] = "static_select" }, chat.RejectUnsupported},
		"details click": {func(p map[string]any) { p["actions"].([]any)[0].(map[string]any)["action_id"] = detailsActionID }, chat.RejectUnsupported},
		"foreign action": {func(p map[string]any) {
			p["actions"].([]any)[0].(map[string]any)["action_id"] = "approve"
		}, chat.RejectMalformed},
		"value mismatch": {func(p map[string]any) { p["actions"].([]any)[0].(map[string]any)["value"] = chattest.Token(9) }, chat.RejectMalformed},
		"bad kind": {func(p map[string]any) {
			p["actions"].([]any)[0].(map[string]any)["action_id"] = "hp1:x:" + chattest.Token(2)
		}, chat.RejectMalformed},
		"short token": {func(p map[string]any) {
			a := p["actions"].([]any)[0].(map[string]any)
			a["action_id"], a["value"] = "hp1:a:abc", "abc"
		}, chat.RejectMalformed},
		"channel mismatch": {func(p map[string]any) { p["channel"] = map[string]any{"id": "C0OTHER"} }, chat.RejectMalformed},
		"no channel": {func(p map[string]any) {
			delete(p, "channel")
			p["container"] = map[string]any{"type": "message", "message_ts": "1.2"}
		}, chat.RejectMalformed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBody(formBody(interaction(c.mut)), parseOpts)
			if chat.ReasonOf(err) != c.want {
				t.Fatalf("reason %v (%v), want %s", chat.ReasonOf(err), err, c.want)
			}
		})
	}
}

func TestParseBodyMalformed(t *testing.T) {
	cases := map[string]chat.RejectReason{
		"":                                     chat.RejectUnsupported,
		"foo=bar":                              chat.RejectUnsupported,
		"payload=%7Bnot-json":                  chat.RejectMalformed,
		"payload=a&payload=b":                  chat.RejectMalformed,
		"payload=%7B%7D&command=%2Fhallpass":   chat.RejectMalformed,
		"payload=%zz":                          chat.RejectMalformed,
		"payload=null":                         chat.RejectUnsupported,
		"payload=%5B%5D":                       chat.RejectMalformed,
		"command=%2Fother&team_id=" + testTeam: chat.RejectUnsupported,
	}
	for body, want := range cases {
		if _, err := ParseBody([]byte(body), parseOpts); chat.ReasonOf(err) != want {
			t.Errorf("%q: %v, want %s", body, err, want)
		}
	}
}

func command(text string, mut func(v url.Values)) []byte {
	v := url.Values{
		"command": {"/hallpass"}, "text": {text}, "team_id": {testTeam}, "user_id": {"U123ABC"}, "user_name": {"alice"},
		"channel_id": {"C0APPROVE"}, "response_url": {"https://hooks.slack.com/commands/T0HALLPASS/1/x"},
	}
	if mut != nil {
		mut(v)
	}
	return []byte(v.Encode())
}

func TestParseCommands(t *testing.T) {
	in, err := ParseBody(command("link ab12cd34", nil), parseOpts)
	if err != nil || !in.IsCommand || in.Event == nil || in.Event.Kind != chat.EventLink {
		t.Fatalf("link: %v %+v", err, in)
	}
	if l := in.Event.Link; l.Code != "AB12CD34" || l.UserID != "U123ABC" || l.Workspace != testTeam || l.ReceivedAt != parseOpts.Now {
		t.Fatalf("link %+v", l)
	}
	req := ids.New(ids.Request)
	in, err = ParseBody(command("STATUS req_"+strings.ToUpper(strings.TrimPrefix(req, "req_")), nil), parseOpts)
	if err != nil || in.Event == nil || in.Event.Status.RequestID != req {
		t.Fatalf("status: %v %+v", err, in)
	}
	for text, wantReply := range map[string]string{
		"":                 HelpText,
		"help":             HelpText,
		"link":             HelpText,
		"link a b":         HelpText,
		"link <!channel>":  "Invalid link code",
		"status agt_x":     "Invalid request ID",
		"approve everyone": HelpText,
	} {
		in, err := ParseBody(command(text, nil), parseOpts)
		if err != nil || in.Event != nil || !strings.HasPrefix(in.LocalReply, wantReply) {
			t.Errorf("%q: %v %+v", text, err, in)
		}
	}
	if _, err := ParseBody(command("link X", func(v url.Values) { v.Set("team_id", "T0OTHER") }), parseOpts); chat.ReasonOf(err) != chat.RejectWorkspace {
		t.Fatal("wrong team accepted", err)
	}
	if _, err := ParseBody(command("link X", func(v url.Values) { v.Del("user_id") }), parseOpts); chat.ReasonOf(err) != chat.RejectMalformed {
		t.Fatal("missing user accepted", err)
	}
	custom := parseOpts
	custom.Command = "/hp"
	if _, err := ParseBody(command("help", nil), custom); chat.ReasonOf(err) != chat.RejectUnsupported {
		t.Fatal("command name not enforced", err)
	}
}

func TestValidResponseURL(t *testing.T) {
	base := DefaultResponseURLBase
	for s, ok := range map[string]bool{
		"https://hooks.slack.com/actions/T1/2/abc":             true,
		"https://hooks.slack.com/commands/T1/2/abc":            true,
		"http://hooks.slack.com/actions/x":                     false,
		"https://hooks.slack.com.evil.example/x":               false,
		"https://evil.example/hooks.slack.com/":                false,
		"https://user@hooks.slack.com/x":                       false,
		"https://hooks.slack.com/x?redirect=evil":              false,
		"https://hooks.slack.com/x#f":                          false,
		"https://hooks.slack.com/actions/../../x":              false,
		"https://hooks.slack.com:8443/x":                       false,
		"":                                                     false,
		"%zz":                                                  false,
		"https://hooks.slack.com/" + strings.Repeat("a", 2001): false,
	} {
		if got := validResponseURL(s, base) != ""; got != ok {
			t.Errorf("validResponseURL(%q) = %v", s, got)
		}
	}
}

func TestActionIDRoundTrip(t *testing.T) {
	for _, k := range []chat.ActionKind{chat.ActionApprove, chat.ActionDeny} {
		kind, tok, ok := ParseActionID(ActionID(k, chattest.Token(7)))
		if !ok || kind != k || tok != chattest.Token(7) {
			t.Fatal(k)
		}
	}
	for _, bad := range []string{"", "hp1:", "hp1:a", "hp1:ab" + chattest.Token(1), "hp2:a:" + chattest.Token(1), "hp1:a:" + strings.Repeat("a", 41)} {
		if _, _, ok := ParseActionID(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if validTS("1.") || validTS("a.1") || validTS("1") || !validTS("1700000000.000100") {
		t.Fatal("validTS")
	}
}

func FuzzParseBody(f *testing.F) {
	f.Add(formBody(interaction(nil)))
	f.Add(command("link ABCD1234", nil))
	f.Add(command("status req_x", nil))
	f.Add([]byte(docBody))
	f.Add([]byte("payload=%7B%22type%22%3A%22block_actions%22%7D"))
	for _, h := range chattest.Hostile[:6] {
		f.Add(command("link "+h, nil))
		f.Add(formBody(interaction(func(p map[string]any) { p["user"] = map[string]any{"id": "U1", "name": h} })))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		in, err := ParseBody(body, parseOpts)
		if err != nil {
			if _, ok := errors.AsType[*chat.RejectError](err); !ok {
				t.Fatalf("non-reject error %T", err)
			}
			return
		}
		if in.ResponseURL != "" && !strings.HasPrefix(in.ResponseURL, DefaultResponseURLBase) {
			t.Fatalf("response url escaped allowlist: %q", in.ResponseURL)
		}
		if in.Event == nil {
			if in.LocalReply == "" {
				t.Fatal("neither event nor reply")
			}
			return
		}
		id := in.Event.Identity()
		if id.Workspace != testTeam || !validSlackID(id.UserID) || !validSlackID(id.ChatID) || len([]rune(id.UserName)) > maxUserName {
			t.Fatalf("bad identity %+v", id)
		}
		if ia := in.Event.Interaction; ia != nil && !chat.ValidActionTokenID(ia.ActionTokenID) {
			t.Fatalf("bad token %q", ia.ActionTokenID)
		}
	})
}

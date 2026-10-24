package notify

import (
	"context"
	"fmt"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

// SR-43: the rejection-audit dedupe table is bounded however many provider users send rejected updates, and
// non-command chatter is not audited at all.
func TestRejectionDedupeBounded(t *testing.T) {
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	svc := New(Deps{Store: s, Keyring: kr, Audit: audit.NewWriter(kr)}, Options{})
	sink := sinkFor{svc: svc, integrationID: "int_x"}
	for i := range 10000 {
		sink.Rejected(context.Background(), chat.Rejection{Provider: chat.ProviderTelegram, Reason: chat.RejectChatNotAllowed,
			Authenticated: true, UserID: fmt.Sprint(i), ChatID: "-1"})
	}
	if n := svc.rejected.Len(); n > 4097 {
		t.Fatalf("rejection dedupe tracks %d keys", n)
	}
	var before int
	if err := s.ReadDB().QueryRow(`SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before > refusalAuditsGlobal {
		t.Fatalf("%d rejection audit rows in one minute, want at most %d", before, refusalAuditsGlobal)
	}
	sink.Rejected(context.Background(), chat.Rejection{Provider: chat.ProviderTelegram, Reason: chat.RejectUnsupported, Authenticated: true,
		UserID: "unique-user", ChatID: "7"})
	var after int
	if err := s.ReadDB().QueryRow(`SELECT count(*) FROM audit_events WHERE json_extract(details_json, '$.reason') = 'unsupported'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Fatal("non-command chatter audited")
	}
}

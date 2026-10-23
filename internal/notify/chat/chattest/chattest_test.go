package chattest

import (
	"context"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

func TestChattestSink(t *testing.T) {
	s := &Sink{Reply: "ok"}
	if s.LastRejection() != "" {
		t.Fatal("empty")
	}
	if s.HandleEvent(context.Background(), chat.Event{Kind: chat.EventLink}).Text != "ok" {
		t.Fatal("reply")
	}
	s.Rejected(context.Background(), chat.Rejection{Reason: chat.RejectReplay})
	ev, rej := s.Snapshot()
	if len(ev) != 1 || len(rej) != 1 || s.LastRejection() != chat.RejectReplay {
		t.Fatal("snapshot")
	}
	if _, err := (FailingReplay{}).Remember(context.Background(), "k", time.Now()); err == nil {
		t.Fatal("failing replay")
	}
	if m := Message(); m.Validate() != nil || len(Token(1)) != 22 {
		t.Fatal("fixtures")
	}
}

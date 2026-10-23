package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/egress"
)

func TestFailureDetailIsClassifiedAndAddressFree(t *testing.T) {
	addr := "10.20.30.40:22"
	for _, tc := range []struct {
		stage string
		err   error
		want  string
	}{
		{"destination connection", fmt.Errorf("dial tcp %s: %w", addr, syscall.ECONNREFUSED), "refused the connection"},
		{"destination connection", fmt.Errorf("dial tcp %s: %w", addr, context.DeadlineExceeded), "timeout"},
		{"destination connection", fmt.Errorf("dial %s: %w", addr, egress.ErrDenied), "egress policy"},
		{"destination connection", &net.DNSError{Err: "no such host", Name: "web1.internal"}, "did not resolve"},
		{"destination connection", fmt.Errorf("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"), "login credential"},
		{"destination connection", errors.New("something else at " + addr), "connection failed"},
		{"login credential", errors.New("no active credential"), "no active login credential"},
		{"recording unavailable", errors.New("disk"), "recording"},
	} {
		got := failureDetail(tc.stage, tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "10.20.30.40") || strings.Contains(got, "web1.internal") {
			t.Errorf("%s / %v: %q", tc.stage, tc.err, got)
		}
	}
	if d := terminationDetail("destination_keepalive_timeout"); !strings.Contains(d, "stopped responding") {
		t.Errorf("termination detail %q", d)
	}
}

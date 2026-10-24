package sshproxy

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestWaitExit(t *testing.T) {
	run := func(reqs ...*ssh.Request) error {
		ch := make(chan *ssh.Request, len(reqs))
		for _, r := range reqs {
			ch <- r
		}
		close(ch)
		return waitExit(ch)
	}
	status := func(n uint32) *ssh.Request {
		return &ssh.Request{Type: "exit-status", Payload: ExitStatusPayload(n)}
	}
	if err := run(&ssh.Request{Type: "keepalive@openssh.com"}, status(0)); err != nil {
		t.Fatalf("status 0: %v", err)
	}
	var re *remoteExit
	if err := run(status(3)); !errors.As(err, &re) || re.status != 3 || re.signal != "" {
		t.Fatalf("status 3: %v", err)
	}
	if err := run(&ssh.Request{Type: "exit-signal", Payload: ExitSignalPayload("TERM", false, "")}); !errors.As(err, &re) || re.signal != "TERM" {
		t.Fatalf("signal: %v", err)
	}
	var missing *ssh.ExitMissingError
	if err := run(); !errors.As(err, &missing) {
		t.Fatalf("no status: %v", err)
	}
}

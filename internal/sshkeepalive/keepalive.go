// Package sshkeepalive probes an SSH peer with keepalive@openssh.com requests to detect dead peers on either leg
// of the gateway (HP-SSH-012).
package sshkeepalive

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
)

// Close reasons returned by Run.
const (
	ReasonFailed  = "keepalive_failed"
	ReasonTimeout = "keepalive_timeout"
)

// Run sends a keepalive every interval until ctx ends, and returns "" then. It returns ReasonFailed when a probe
// fails (the transport is gone) and ReasonTimeout after maxMissed consecutive probes got no reply within an
// interval. The caller closes the connection. A non-positive interval disables probing.
func Run(ctx context.Context, conn ssh.Conn, interval time.Duration, maxMissed int) string {
	if interval <= 0 {
		<-ctx.Done()
		return ""
	}
	if maxMissed <= 0 {
		maxMissed = 3
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-t.C:
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ""
		case err := <-done:
			timer.Stop()
			if err != nil {
				return ReasonFailed
			}
			missed = 0
		case <-timer.C:
			missed++
			if missed >= maxMissed {
				return ReasonTimeout
			}
		}
	}
}

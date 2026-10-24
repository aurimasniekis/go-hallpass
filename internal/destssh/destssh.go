// Package destssh opens outbound SSH connections to destinations with strict host verification, the egress guard
// and gateway-held credentials (HP-SSH-011, HP-SRV-009). It is the only outbound SSH dialer in HallPass.
package destssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/sshalg"
)

// ClientVersion is the SSH identification string sent to destinations.
const ClientVersion = "SSH-2.0-Hallpass"

// Target describes one destination login.
type Target struct {
	Host     string
	Port     int
	User     string
	Verifier *inventory.Verifier
	Signers  []ssh.Signer
}

// ErrNoVerifier is returned when a dial lacks host verification; it is never skipped.
var ErrNoVerifier = errors.New("destination host verification is required")

// Dial resolves and connects through guard, verifies the host key with t.Verifier and authenticates with t.Signers.
// The handshake must complete within timeout.
func Dial(ctx context.Context, guard *egress.Guard, t Target, timeout time.Duration) (*ssh.Client, error) {
	if t.Verifier == nil || t.Verifier.Callback == nil {
		return nil, ErrNoVerifier
	}
	if len(t.Signers) == 0 {
		return nil, errors.New("no login credential available for this role")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := guard.Dial(dctx, t.Host, t.Port)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cfg := &ssh.ClientConfig{
		Config:            sshalg.Config(),
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(RestrictRSA(t.Signers)...)},
		HostKeyCallback:   t.Verifier.Callback,
		HostKeyAlgorithms: t.Verifier.Algorithms,
		ClientVersion:     ClientVersion,
		Timeout:           timeout,
	}
	type result struct {
		c     ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), cfg)
		done <- result{c, chans, reqs, err}
	}()
	select {
	case <-dctx.Done():
		_ = conn.Close()
		<-done
		return nil, fmt.Errorf("destination handshake: %w", dctx.Err())
	case r := <-done:
		if r.err != nil {
			_ = conn.Close()
			return nil, r.err
		}
		_ = conn.SetDeadline(time.Time{})
		return ssh.NewClient(r.c, r.chans, r.reqs), nil
	}
}

// RestrictRSA limits plain RSA signers to rsa-sha2-512/256 so a destination that sends no server-sig-algs cannot
// make the gateway sign with SHA-1 "ssh-rsa" (HP-SSH-004 on the destination leg, SR-45). Other signers are returned
// unchanged.
func RestrictRSA(signers []ssh.Signer) []ssh.Signer {
	out := make([]ssh.Signer, 0, len(signers))
	for _, s := range signers {
		if as, ok := s.(ssh.AlgorithmSigner); ok && s.PublicKey().Type() == ssh.KeyAlgoRSA {
			if ms, err := ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}); err == nil {
				out = append(out, ms)
				continue
			}
			continue // never fall back to an unrestricted RSA signer
		}
		out = append(out, s)
	}
	return out
}

// IsHostKeyError reports whether err is a host verification failure and returns its details.
func IsHostKeyError(err error) (*inventory.HostKeyError, bool) {
	var he *inventory.HostKeyError
	if errors.As(err, &he) {
		return he, true
	}
	return nil, false
}

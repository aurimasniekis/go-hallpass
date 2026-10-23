package sshkeepalive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pair returns a connected client and the server's global-request channel.
func pair(t *testing.T) (ssh.Conn, <-chan *ssh.Request, net.Conn) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = b.Close() })
	type res struct {
		reqs <-chan *ssh.Request
		err  error
	}
	srvDone := make(chan res, 1)
	go func() {
		_, chans, reqs, err := ssh.NewServerConn(b, cfg)
		if err == nil {
			go func() {
				for c := range chans {
					_ = c.Reject(ssh.Prohibited, "")
				}
			}()
		}
		srvDone <- res{reqs, err}
	}()
	pub := signer.PublicKey()
	cc, _, creqs, err := ssh.NewClientConn(a, "pipe", &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.FixedHostKey(pub)})
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(creqs)
	r := <-srvDone
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc, r.reqs, a
}

func TestRunAnsweredUntilCanceled(t *testing.T) {
	c, reqs, _ := pair(t)
	var answered atomic.Int32
	go func() {
		for r := range reqs {
			answered.Add(1)
			_ = r.Reply(false, nil) // OpenSSH replies failure to unknown requests: still proof of life
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if got := Run(ctx, c, 20*time.Millisecond, 2); got != "" {
		t.Fatalf("live peer: %q", got)
	}
	if answered.Load() < 3 {
		t.Fatalf("probes answered: %d", answered.Load())
	}
}

// A peer that stops answering (hung host, dropped network) is detected after maxMissed intervals.
func TestRunDetectsSilentPeer(t *testing.T) {
	c, reqs, _ := pair(t)
	go func() {
		for range reqs { // read but never reply
		}
	}()
	start := time.Now()
	if got := Run(context.Background(), c, 20*time.Millisecond, 3); got != ReasonTimeout {
		t.Fatalf("silent peer: %q", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("detection took %v", d)
	}
}

func TestRunDetectsClosedTransport(t *testing.T) {
	c, reqs, raw := pair(t)
	go func() {
		for range reqs {
		}
	}()
	_ = raw.Close()
	if got := Run(context.Background(), c, 10*time.Millisecond, 100); got != ReasonFailed && got != ReasonTimeout {
		t.Fatalf("closed transport: %q", got)
	}
}

func TestRunDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Run(ctx, nil, 0, 0); got != "" {
		t.Fatalf("disabled: %q", got)
	}
}

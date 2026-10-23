// Package sshtest runs an in-process SSH server that stands in for a destination in unit tests. Real OpenSSH
// interoperability is covered by test/openssh.
package sshtest

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

// Login records one successful authentication.
type Login struct {
	User        string
	Fingerprint string
	CertKeyID   string
	Principals  []string
}

// ExecFunc handles an exec request and returns the exit status.
type ExecFunc func(cmd string, stdin io.Reader, stdout, stderr io.Writer) uint32

// Server is a destination test server.
type Server struct {
	t        testing.TB
	ln       net.Listener
	cfg      *ssh.ServerConfig
	HostKeys []sshkeys.Key

	mu         sync.Mutex
	authorized map[string]bool // fingerprint → allowed
	userCA     ssh.PublicKey
	principals map[string][]string // user → accepted principals
	logins     []Login
	envs       [][2]string
	Exec       ExecFunc
	// ExitSignal, when set and returning a signal name for a command, ends that exec with exit-signal instead of
	// exit-status.
	ExitSignal func(cmd string) string
	// Unresponsive, when set, makes the server read global requests (keepalives) without ever replying: a hung
	// host whose TCP connection stays open.
	Unresponsive atomic.Bool
	wg           sync.WaitGroup
}

// Envs returns the environment variables sessions requested, in order.
func (s *Server) Envs() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.envs)
}

// Start launches a server on 127.0.0.1 with the given host keys (one Ed25519 key when none).
func Start(t testing.TB, hostKeys ...sshkeys.Key) *Server {
	t.Helper()
	if len(hostKeys) == 0 {
		hostKeys = []sshkeys.Key{sshkeys.Ed25519(t)}
	}
	s := &Server{t: t, HostKeys: hostKeys, authorized: map[string]bool{}, principals: map[string][]string{}}
	s.Exec = func(cmd string, _ io.Reader, stdout, _ io.Writer) uint32 {
		_, _ = fmt.Fprintf(stdout, "ran: %s\n", cmd)
		return 0
	}
	s.cfg = &ssh.ServerConfig{PublicKeyCallback: s.auth, ServerVersion: "SSH-2.0-OpenSSH_9.6 sshtest"}
	for _, k := range hostKeys {
		s.cfg.AddHostKey(k.Signer)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// Addr returns host and port.
func (s *Server) Addr() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// Close stops the server.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

// Authorize allows a public key (authorized_keys).
func (s *Server) Authorize(pk ssh.PublicKey) {
	s.mu.Lock()
	s.authorized[ssh.FingerprintSHA256(pk)] = true
	s.mu.Unlock()
}

// TrustUserCA accepts user certificates from ca; principals maps login user to accepted principals
// (AuthorizedPrincipalsFile semantics).
func (s *Server) TrustUserCA(ca ssh.PublicKey, principals map[string][]string) {
	s.mu.Lock()
	s.userCA = ca
	s.principals = principals
	s.mu.Unlock()
}

// Logins returns successful logins.
func (s *Server) Logins() []Login {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.logins)
}

func (s *Server) auth(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cert, ok := key.(*ssh.Certificate); ok {
		if s.userCA == nil {
			return nil, errors.New("certificates not trusted")
		}
		checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), s.userCA.Marshal()) }}
		for _, p := range s.principals[meta.User()] {
			perms, err := checker.Authenticate(fakeMeta{meta, p}, key)
			if err == nil {
				s.logins = append(s.logins, Login{User: meta.User(), Fingerprint: ssh.FingerprintSHA256(cert.Key), CertKeyID: cert.KeyId, Principals: cert.ValidPrincipals})
				return perms, nil
			}
		}
		return nil, errors.New("certificate not accepted")
	}
	fp := ssh.FingerprintSHA256(key)
	if !s.authorized[fp] {
		return nil, errors.New("unknown key")
	}
	s.logins = append(s.logins, Login{User: meta.User(), Fingerprint: fp})
	return &ssh.Permissions{}, nil
}

type fakeMeta struct {
	ssh.ConnMetadata
	user string
}

func (f fakeMeta) User() string { return f.user }

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for r := range reqs {
			if r.WantReply && !s.Unresponsive.Load() {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go s.session(ch, creqs)
	}
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Cmd string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			status := s.Exec(p.Cmd, ch, ch, ch.Stderr())
			_ = ch.CloseWrite()
			if s.ExitSignal != nil {
				if sig := s.ExitSignal(p.Cmd); sig != "" {
					_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
						Signal     string
						CoreDumped bool
						Msg, Lang  string
					}{Signal: sig}))
					return
				}
			}
			_, _ = ch.SendRequest("exit-status", false, exitStatus(status))
			return
		case "shell":
			_ = req.Reply(true, nil)
			_, _ = io.Copy(ch, ch)
			_, _ = ch.SendRequest("exit-status", false, exitStatus(0))
			return
		case "env":
			var e struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &e) == nil {
				s.mu.Lock()
				s.envs = append(s.envs, [2]string{e.Name, e.Value})
				s.mu.Unlock()
			}
			_ = req.Reply(true, nil)
		case "pty-req", "window-change":
			_ = req.Reply(req.Type != "window-change", nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func exitStatus(code uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, code)
	return b
}

// KnownHostsLine returns an authorized_keys-style line for host key i.
func (s *Server) KnownHostsLine(i int) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.HostKeys[i].Public)))
}

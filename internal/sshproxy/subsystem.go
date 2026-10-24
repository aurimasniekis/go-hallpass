package sshproxy

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// remoteSession is the destination side of a channel. *ssh.Session serves shells and commands; subsystemSession
// serves subsystems, because ssh.Session.RequestSubsystem never marks the session started and its Wait then cannot
// report the exit status.
type remoteSession interface {
	RequestPty(term string, h, w int, modes ssh.TerminalModes) error
	Setenv(name, value string) error
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	StderrPipe() (io.Reader, error)
	WindowChange(h, w int) error
	Signal(sig ssh.Signal) error
	Wait() error
	Close() error
}

// remoteExit is how a subsystem session ended (ssh.ExitError cannot be constructed outside x/crypto).
type remoteExit struct {
	status int
	signal string
}

func (e *remoteExit) Error() string {
	if e.signal != "" {
		return "remote exited on signal " + e.signal
	}
	return fmt.Sprintf("remote exited with status %d", e.status)
}

// subsystemSession is a raw session channel running one subsystem; it tracks exit-status and exit-signal itself.
type subsystemSession struct {
	ch   ssh.Channel
	exit chan error
}

func newSubsystemSession(client *ssh.Client) (*subsystemSession, error) {
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		return nil, err
	}
	s := &subsystemSession{ch: ch, exit: make(chan error, 1)}
	go func() { s.exit <- waitExit(reqs) }()
	return s, nil
}

// waitExit reads the destination's channel requests until the channel closes and returns how it ended: nil for status
// 0, *remoteExit otherwise, or *ssh.ExitMissingError when the destination never said.
func waitExit(reqs <-chan *ssh.Request) error {
	var res *remoteExit
	for r := range reqs {
		switch r.Type {
		case "exit-status":
			var m struct{ Status uint32 }
			if ssh.Unmarshal(r.Payload, &m) == nil {
				res = &remoteExit{status: int(m.Status)} //nolint:gosec // exit codes are 0..255
			}
		case "exit-signal":
			var m struct {
				Signal     string
				CoreDumped bool
				Error      string
				Lang       string
			}
			if ssh.Unmarshal(r.Payload, &m) == nil {
				res = &remoteExit{status: -1, signal: m.Signal}
			}
		}
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
	switch {
	case res == nil:
		return &ssh.ExitMissingError{}
	case res.signal == "" && res.status == 0:
		return nil
	}
	return res
}

// Start requests the subsystem.
func (s *subsystemSession) Start(name string) error {
	ok, err := s.ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{name}))
	if err == nil && !ok {
		err = errors.New("ssh: subsystem request failed")
	}
	return err
}

func (s *subsystemSession) RequestPty(string, int, int, ssh.TerminalModes) error {
	return errors.New("subsystems run without a terminal")
}

func (s *subsystemSession) Setenv(string, string) error {
	return errors.New("subsystems get no environment")
}

func (s *subsystemSession) StdinPipe() (io.WriteCloser, error) { return halfCloser{s.ch}, nil }

func (s *subsystemSession) StdoutPipe() (io.Reader, error) { return s.ch, nil }

func (s *subsystemSession) StderrPipe() (io.Reader, error) { return s.ch.Stderr(), nil }

func (s *subsystemSession) WindowChange(int, int) error {
	return errors.New("subsystems run without a terminal")
}

func (s *subsystemSession) Signal(sig ssh.Signal) error {
	_, err := s.ch.SendRequest("signal", false, ssh.Marshal(struct{ Signal string }{string(sig)}))
	return err
}

func (s *subsystemSession) Wait() error { return <-s.exit }

func (s *subsystemSession) Close() error { return s.ch.Close() }

// halfCloser closes only the write side, sending EOF to the destination (as ssh.Session's stdin pipe does).
type halfCloser struct{ ch ssh.Channel }

func (h halfCloser) Write(p []byte) (int, error) { return h.ch.Write(p) }

func (h halfCloser) Close() error { return h.ch.CloseWrite() }

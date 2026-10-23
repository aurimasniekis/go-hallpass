package sshproxy

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/ssh"
)

// PTYRequest is an agent's pty-req (RFC 4254 §6.2).
type PTYRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  ssh.TerminalModes
}

type ptyReqMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// ParsePTYRequest decodes a pty-req payload. Terminal names are bounded and the mode list is validated.
func ParsePTYRequest(payload []byte) (*PTYRequest, error) {
	var m ptyReqMsg
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	if len(m.Term) > 64 || m.Columns > 10000 || m.Rows > 10000 {
		return nil, errors.New("pty request out of bounds")
	}
	modes, err := parseModes([]byte(m.Modelist))
	if err != nil {
		return nil, err
	}
	return &PTYRequest{Term: m.Term, Cols: m.Columns, Rows: m.Rows, Width: m.Width, Height: m.Height, Modes: modes}, nil
}

// parseModes decodes the encoded terminal modes: (opcode u8, value u32)* terminated by TTY_OP_END (0).
func parseModes(b []byte) (ssh.TerminalModes, error) {
	modes := ssh.TerminalModes{}
	for len(b) > 0 {
		op := b[0]
		if op == 0 {
			return modes, nil
		}
		if op >= 160 || len(b) < 5 {
			// Opcodes 160+ have undefined argument layouts; stop parsing rather than guess.
			return modes, nil
		}
		modes[op] = binary.BigEndian.Uint32(b[1:5])
		b = b[5:]
		if len(modes) > 256 {
			return nil, errors.New("too many terminal modes")
		}
	}
	return modes, nil
}

// WindowChange is a window-change request.
type WindowChange struct {
	Cols, Rows, Width, Height uint32
}

// ParseWindowChange decodes a window-change payload.
func ParseWindowChange(payload []byte) (*WindowChange, error) {
	var m struct{ Columns, Rows, Width, Height uint32 }
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	if m.Columns > 10000 || m.Rows > 10000 {
		return nil, errors.New("window size out of bounds")
	}
	return &WindowChange{Cols: m.Columns, Rows: m.Rows, Width: m.Width, Height: m.Height}, nil
}

// ParseEnv decodes an env request.
func ParseEnv(payload []byte) (name, value string, err error) {
	var m struct{ Name, Value string }
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return "", "", err
	}
	return m.Name, m.Value, nil
}

// ParseSignal decodes a signal request.
func ParseSignal(payload []byte) (ssh.Signal, error) {
	var m struct{ Signal string }
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return "", err
	}
	switch ssh.Signal(m.Signal) {
	case ssh.SIGABRT, ssh.SIGALRM, ssh.SIGFPE, ssh.SIGHUP, ssh.SIGILL, ssh.SIGINT, ssh.SIGKILL, ssh.SIGPIPE, ssh.SIGQUIT,
		ssh.SIGSEGV, ssh.SIGTERM, ssh.SIGUSR1, ssh.SIGUSR2:
		return ssh.Signal(m.Signal), nil
	}
	return "", errors.New("unknown signal")
}

// ExitStatusPayload encodes exit-status.
func ExitStatusPayload(code uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, code)
	return b
}

// ExitSignalPayload encodes exit-signal (RFC 4254 §6.10).
func ExitSignalPayload(sig string, coreDumped bool, msg string) []byte {
	return ssh.Marshal(struct {
		Signal     string
		CoreDumped bool
		Error      string
		Lang       string
	}{sig, coreDumped, msg, ""})
}

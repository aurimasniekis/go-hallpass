// Package webterm adapts a browser WebSocket to the ssh.Channel the SSH data plane (sshproxy) forwards to a
// destination, so an administrator's web terminal (ADR-0055) runs through exactly the same recording, enforcement and
// destination login as an agent's shell.
//
// Protocol (the browser speaks it in web/src/features/terminal):
//
//	browser → server  text frames, JSON: {"type":"input","data":"<UTF-8 text>"}, {"type":"resize","cols":C,"rows":R}
//	server → browser  binary frames: terminal output; text frames, JSON: {"type":"exit","status":N} or
//	                  {"type":"exit","signal":"…"}, and {"type":"ping"} every 25 s to keep proxies from idling out
package webterm

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// Limits.
const (
	// MaxFrame bounds one browser frame (a paste).
	MaxFrame = 64 << 10
	// MaxDimension bounds terminal columns and rows.
	MaxDimension = 1000
	pingEvery    = 25 * time.Second
)

// Channel is an ssh.Channel backed by a WebSocket.
type Channel struct {
	ws    *websocket.Conn
	wmu   sync.Mutex
	in    *io.PipeReader
	inW   *io.PipeWriter
	reqs  chan *ssh.Request
	done  chan struct{}
	once  sync.Once
	first chan [2]uint32
}

type message struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint32 `json:"cols,omitempty"`
	Rows uint32 `json:"rows,omitempty"`
}

// New starts reading browser frames from ws. Call InitialSize to wait for the first resize (the PTY size).
func New(ws *websocket.Conn) *Channel {
	ws.MaxPayloadBytes = MaxFrame
	r, w := io.Pipe()
	c := &Channel{ws: ws, in: r, inW: w, reqs: make(chan *ssh.Request, 16), done: make(chan struct{}), first: make(chan [2]uint32, 1)}
	go c.readLoop()
	go c.pingLoop()
	return c
}

func (c *Channel) readLoop() {
	defer func() {
		_ = c.inW.Close()
		close(c.reqs)
		c.shutdown()
	}()
	sized := false
	for {
		var raw string
		if err := websocket.Message.Receive(c.ws, &raw); err != nil {
			return
		}
		var m message
		if json.Unmarshal([]byte(raw), &m) != nil {
			return // a malformed frame ends the terminal
		}
		switch m.Type {
		case "input":
			if _, err := c.inW.Write([]byte(m.Data)); err != nil {
				return
			}
		case "resize":
			if m.Cols == 0 || m.Rows == 0 || m.Cols > MaxDimension || m.Rows > MaxDimension {
				continue
			}
			if !sized {
				sized = true
				c.first <- [2]uint32{m.Cols, m.Rows}
				continue
			}
			payload := ssh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{m.Cols, m.Rows, 0, 0})
			select {
			case c.reqs <- &ssh.Request{Type: "window-change", Payload: payload}:
			default: // resizes coalesce; dropping one under a burst is harmless
			}
		}
	}
}

func (c *Channel) pingLoop() {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if c.sendControl(map[string]any{"type": "ping"}) != nil {
				return
			}
		}
	}
}

// ErrClosed is returned when the browser went away before sending the terminal size.
var ErrClosed = errors.New("web terminal closed")

// InitialSize waits for the browser's first resize, which sets the PTY size.
func (c *Channel) InitialSize(timeout time.Duration) (cols, rows uint32, err error) {
	select {
	case s := <-c.first:
		return s[0], s[1], nil
	case <-c.done:
		return 0, 0, ErrClosed
	case <-time.After(timeout):
		return 0, 0, errors.New("the browser did not send the terminal size")
	}
}

// Requests returns window-change requests from the browser; it closes when the browser disconnects.
func (c *Channel) Requests() <-chan *ssh.Request { return c.reqs }

// Done is closed when the WebSocket is closed.
func (c *Channel) Done() <-chan struct{} { return c.done }

func (c *Channel) shutdown() {
	c.once.Do(func() {
		close(c.done)
		_ = c.ws.Close()
	})
}

func (c *Channel) sendControl(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return websocket.Message.Send(c.ws, string(b))
}

// Read returns what the operator typed.
func (c *Channel) Read(p []byte) (int, error) { return c.in.Read(p) }

// Write sends terminal output to the browser.
func (c *Channel) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := websocket.Message.Send(c.ws, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the terminal.
func (c *Channel) Close() error {
	c.shutdown()
	return nil
}

// CloseWrite is a no-op: the exit message follows.
func (c *Channel) CloseWrite() error { return nil }

// SendRequest delivers exit-status and exit-signal to the browser; other requests are ignored.
func (c *Channel) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	switch name {
	case "exit-status":
		var m struct{ Status uint32 }
		if ssh.Unmarshal(payload, &m) == nil {
			return true, c.sendControl(map[string]any{"type": "exit", "status": m.Status})
		}
	case "exit-signal":
		var m struct {
			Signal     string
			CoreDumped bool
			Error      string
			Lang       string
		}
		if ssh.Unmarshal(payload, &m) == nil {
			return true, c.sendControl(map[string]any{"type": "exit", "signal": m.Signal})
		}
	}
	return false, nil
}

// Stderr is the same stream as Write: a terminal has one screen.
func (c *Channel) Stderr() io.ReadWriter { return stderr{c} }

type stderr struct{ c *Channel }

func (s stderr) Read([]byte) (int, error)    { return 0, io.EOF }
func (s stderr) Write(p []byte) (int, error) { return s.c.Write(p) }

var _ ssh.Channel = (*Channel)(nil)

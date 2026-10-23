package sshproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/destssh"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
)

// failureDetail classifies why a channel failed before it started into a short, stable, address-free sentence for
// operators (stored as ssh_channels.close_detail). Raw errors stay in the gateway log: they can contain addresses
// that operators without inventory.address.read must not see (HP-SRV-010).
func failureDetail(stage string, err error) string {
	switch stage {
	case "recording unavailable", "recording exec":
		return "recording could not be started (mandatory recording)"
	case "server lookup":
		return "server not found"
	case "host identity":
		return "no usable host identity for the server (enroll or confirm its host key)"
	case "login credential":
		return "no active login credential for the role"
	case "destination connection":
		return dialDetail(err)
	case "destination session":
		return "destination refused to open a session"
	case "destination pty":
		return "destination refused the terminal (PTY) request"
	case "start":
		return "destination refused to start the shell or command"
	case "activate", "access ended":
		return "access ended before the channel started"
	}
	return "channel setup failed (" + stage + ")"
}

// dialDetail classifies destination connection errors.
func dialDetail(err error) string {
	var ne net.Error
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return "destination connection failed"
	case errors.Is(err, egress.ErrDenied):
		return "destination address not permitted by the egress policy"
	}
	if _, ok := destssh.IsHostKeyError(err); ok {
		return "destination host key changed or unknown (host verification failed)"
	}
	switch {
	case errors.As(err, &dnsErr):
		return "destination name did not resolve"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "destination refused the connection (nothing listening on the SSH port?)"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "destination unreachable (no route)"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "destination unreachable (timeout)"
	case isAuthError(err):
		return "destination refused the login credential (check authorized_keys or certificate trust)"
	case errors.Is(err, syscall.ECONNRESET), strings.Contains(err.Error(), "handshake failed"):
		return "SSH handshake with the destination failed"
	}
	return "destination connection failed"
}

func isAuthError(err error) bool {
	var se *ssh.ServerAuthError
	return errors.As(err, &se) || strings.Contains(err.Error(), "unable to authenticate")
}

// terminationDetail describes why the gateway ended an active channel.
func terminationDetail(reason string) string {
	switch reason {
	case "recording_failed":
		return "recording failed; mandatory recording ends the channel"
	case "idle_timeout":
		return "idle timeout"
	case "agent_disconnected":
		return "agent disconnected"
	case "destination_keepalive_timeout":
		return "destination stopped responding (keepalive timeout)"
	case "destination_keepalive_failed":
		return "destination connection lost"
	case access.ReasonExpired:
		return "grant expired"
	case access.ReasonOperator:
		return "grant revoked by an operator"
	case access.ReasonAgentDisabled:
		return "agent disabled"
	}
	return strings.ReplaceAll(reason, "_", " ")
}

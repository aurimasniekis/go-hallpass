package sshproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

// SR-08 (HP-SRV-010): the host-key alert audit row carries the address-free classification, not the raw dial
// error with the destination host:port.
func TestHostKeyAlertAuditIsAddressFree(t *testing.T) {
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	p := New(Options{Store: s, Audit: audit.NewWriter(kr)})
	err := fmt.Errorf("ssh: handshake failed with 10.9.8.7:2222: %w", &inventory.HostKeyError{ServerID: "srv_x", Presented: "SHA256:abc",
		Algorithm: "ssh-ed25519", Reason: "host key changed or unknown"})
	p.hostKeyAlert(context.Background(), nil, "srv_x", err)
	var details string
	if err := s.ReadDB().QueryRowContext(context.Background(),
		`SELECT details_json FROM audit_events WHERE action = 'server.host_key_mismatch'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "10.9.8.7") || strings.Contains(details, "2222") {
		t.Fatalf("audit details contain the destination address: %s", details)
	}
	if !strings.Contains(details, "SHA256:abc") || !strings.Contains(details, "host verification failed") {
		t.Fatalf("details lost the classification: %s", details)
	}
}

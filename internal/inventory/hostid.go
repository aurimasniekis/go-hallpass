package inventory

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/sshalg"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// HostIdentity is an enrolled destination host key (HP-SRV-004).
type HostIdentity struct {
	ID          string     `json:"id"`
	ServerID    string     `json:"server_id"`
	Algorithm   string     `json:"algorithm"`
	PublicKey   string     `json:"public_key"`
	Fingerprint string     `json:"fingerprint"`
	State       string     `json:"state"`
	EnrolledVia string     `json:"enrolled_via"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	ConfirmedBy string     `json:"confirmed_by,omitempty"`
}

// HostCA is a host certificate authority trusted for bound servers (HP-SRV-007).
type HostCA struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	PublicKey   string        `json:"public_key"`
	Fingerprint string        `json:"fingerprint"`
	MaxValidity time.Duration `json:"max_validity"`
	State       string        `json:"state"`
}

// ParseHostKey accepts an authorized_keys-style line ("type base64 [comment]") or a known_hosts line.
func ParseHostKey(line string) (ssh.PublicKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, "\n") {
		return nil, apperr.New(apperr.CodeInvalid, "exactly one host key line is required")
	}
	if pk, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil && len(opts) == 0 && len(bytes.TrimSpace(rest)) == 0 {
		return checkHostKeyType(pk)
	}
	if _, _, pk, _, rest, err := ssh.ParseKnownHosts([]byte(line)); err == nil && len(bytes.TrimSpace(rest)) == 0 {
		return checkHostKeyType(pk)
	}
	return nil, apperr.New(apperr.CodeInvalid, "not a valid SSH host public key or known_hosts line")
}

func checkHostKeyType(pk ssh.PublicKey) (ssh.PublicKey, error) {
	switch pk.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return pk, nil
	}
	return nil, apperr.New(apperr.CodeInvalid, "host key type %q is not supported", pk.Type())
}

// AddHostIdentity enrolls a host key supplied by an operator (paste). It becomes active immediately, subject to
// duplicate detection.
func (svc *Service) AddHostIdentity(ctx context.Context, actor audit.Actor, serverID, line string) (*HostIdentity, error) {
	pk, err := ParseHostKey(line)
	if err != nil {
		return nil, err
	}
	var id string
	err = svc.s.W().TxNamed(ctx, "inventory.add_host_identity", func(tx *store.Tx) error {
		if _, err := tx.Q.GetServer(ctx, serverID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		fp := ssh.FingerprintSHA256(pk)
		if existing, err := tx.Q.GetHostIdentityByFingerprint(ctx, db.GetHostIdentityByFingerprintParams{ServerID: serverID, FingerprintSha256: fp}); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "host key %s is already enrolled for this server (state %s)", fp, existing.State)
		}
		if err := svc.checkDuplicate(ctx, tx, serverID, fp); err != nil {
			return err
		}
		id = ids.New(ids.HostIdentity)
		now := sql.NullInt64{Int64: tx.NowMicros(), Valid: true}
		if err := tx.Q.InsertHostIdentity(ctx, db.InsertHostIdentityParams{
			ID: id, ServerID: serverID, Algorithm: pk.Type(), PublicKey: marshalKey(pk), FingerprintSha256: fp, State: "active",
			EnrolledVia: "paste", CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), ConfirmedAt: now,
			ConfirmedBy: sql.NullString{String: actorRef(actor), Valid: true},
		}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_identity.enrolled", Target: audit.Target{Type: "server", ID: serverID},
			Details: map[string]any{"host_identity_id": id, "fingerprint": fp, "algorithm": pk.Type(), "via": "paste"}})
		svc.publish(tx, eventbus.TopicInventoryChanged, serverID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.getHostIdentity(ctx, id)
}

// ConfirmHostIdentity activates a scanned (pending) identity after the operator verified its fingerprint out of band.
func (svc *Service) ConfirmHostIdentity(ctx context.Context, actor audit.Actor, hidID string) (*HostIdentity, error) {
	err := svc.s.W().TxNamed(ctx, "inventory.confirm_host_identity", func(tx *store.Tx) error {
		h, err := tx.Q.GetHostIdentity(ctx, hidID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "host identity not found")
		} else if err != nil {
			return err
		}
		if h.State != "pending" {
			return apperr.New(apperr.CodePrecondition, "host identity is %s, not pending", h.State)
		}
		if err := svc.checkDuplicate(ctx, tx, h.ServerID, h.FingerprintSha256); err != nil {
			return err
		}
		if _, err := tx.Q.ConfirmHostIdentity(ctx, db.ConfirmHostIdentityParams{
			ConfirmedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, ConfirmedBy: sql.NullString{String: actorRef(actor), Valid: true}, ID: hidID,
		}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_identity.confirmed", Target: audit.Target{Type: "server", ID: h.ServerID},
			Details: map[string]any{"host_identity_id": hidID, "fingerprint": h.FingerprintSha256}})
		svc.publish(tx, eventbus.TopicInventoryChanged, h.ServerID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.getHostIdentity(ctx, hidID)
}

// RetireHostIdentity stops trusting a host key (rotation end or compromise).
func (svc *Service) RetireHostIdentity(ctx context.Context, actor audit.Actor, hidID string) (*HostIdentity, error) {
	err := svc.s.W().TxNamed(ctx, "inventory.retire_host_identity", func(tx *store.Tx) error {
		h, err := tx.Q.GetHostIdentity(ctx, hidID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "host identity not found")
		} else if err != nil {
			return err
		}
		n, err := tx.Q.RetireHostIdentity(ctx, db.RetireHostIdentityParams{
			RetiredAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, RetiredBy: sql.NullString{String: actorRef(actor), Valid: true}, ID: hidID,
		})
		if err != nil || n == 0 {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_identity.retired", Target: audit.Target{Type: "server", ID: h.ServerID},
			Details: map[string]any{"host_identity_id": hidID, "fingerprint": h.FingerprintSha256}})
		svc.publish(tx, eventbus.TopicInventoryChanged, h.ServerID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.getHostIdentity(ctx, hidID)
}

// checkDuplicate rejects a fingerprint already active on another server unless an audited exception exists (HP-SRV-006).
func (svc *Service) checkDuplicate(ctx context.Context, tx *store.Tx, serverID, fp string) error {
	others, err := tx.Q.ActiveHostIdentitiesByFingerprint(ctx, fp)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.ServerID == serverID {
			continue
		}
		a, b := orderPair(serverID, o.ServerID)
		n, err := tx.Q.HasHostDuplicateException(ctx, db.HasHostDuplicateExceptionParams{FingerprintSha256: fp, ServerA: a, ServerB: b})
		if err != nil {
			return err
		}
		if n == 0 {
			other, _ := tx.Q.GetServer(ctx, o.ServerID)
			return apperr.New(apperr.CodeConflict, "host key %s is already enrolled for server %q; duplicate host identities require an explicit, justified exception", fp, other.Alias)
		}
	}
	return nil
}

func orderPair(a, b string) (string, string) {
	if a < b {
		return a, b
	}
	return b, a
}

// AddDuplicateException permits the same host key on two servers (e.g. a VIP fronting identical hosts).
func (svc *Service) AddDuplicateException(ctx context.Context, actor audit.Actor, fingerprint, serverA, serverB, justification string) error {
	justification = strings.TrimSpace(justification)
	if len(justification) < 10 || len(justification) > 1000 {
		return apperr.New(apperr.CodeInvalid, "a justification of 10-1000 characters is required")
	}
	if serverA == serverB || !strings.HasPrefix(fingerprint, "SHA256:") {
		return apperr.New(apperr.CodeInvalid, "two distinct servers and a SHA256 fingerprint are required")
	}
	a, b := orderPair(serverA, serverB)
	return svc.s.W().TxNamed(ctx, "inventory.duplicate_exception", func(tx *store.Tx) error {
		for _, sid := range []string{a, b} {
			if _, err := tx.Q.GetServer(ctx, sid); errors.Is(err, sql.ErrNoRows) {
				return apperr.New(apperr.CodeNotFound, "server %s not found", sid)
			} else if err != nil {
				return err
			}
		}
		id := ids.New(ids.HostDupExcept)
		if err := tx.Q.InsertHostDuplicateException(ctx, db.InsertHostDuplicateExceptionParams{
			ID: id, FingerprintSha256: fingerprint, ServerA: a, ServerB: b, Justification: justification,
			CreatedBy: actorRef(actor), CreatedAt: tx.NowMicros(),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "exception already exists")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_identity.duplicate_exception", Target: audit.Target{Type: "server", ID: a},
			Details: map[string]any{"fingerprint": fingerprint, "server_a": a, "server_b": b}, Sensitive: map[string]any{"justification": justification}})
		return err
	})
}

// ListHostIdentities returns all identities of a server.
func (svc *Service) ListHostIdentities(ctx context.Context, serverID string) ([]*HostIdentity, error) {
	rows, err := svc.s.R().ListHostIdentities(ctx, serverID)
	if err != nil {
		return nil, err
	}
	out := make([]*HostIdentity, 0, len(rows))
	for _, r := range rows {
		out = append(out, hostIdentityFromRow(r))
	}
	return out, nil
}

func (svc *Service) getHostIdentity(ctx context.Context, id string) (*HostIdentity, error) {
	r, err := svc.s.R().GetHostIdentity(ctx, id)
	if err != nil {
		return nil, err
	}
	return hostIdentityFromRow(r), nil
}

func hostIdentityFromRow(r db.HostIdentity) *HostIdentity {
	h := &HostIdentity{
		ID: r.ID, ServerID: r.ServerID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Fingerprint: r.FingerprintSha256,
		State: r.State, EnrolledVia: r.EnrolledVia, CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), CreatedBy: r.CreatedBy,
		ConfirmedBy: r.ConfirmedBy.String,
	}
	if r.ConfirmedAt.Valid {
		t := time.UnixMicro(r.ConfirmedAt.Int64).UTC()
		h.ConfirmedAt = &t
	}
	return h
}

func marshalKey(pk ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// CreateHostCA enrolls a host certificate authority public key.
func (svc *Service) CreateHostCA(ctx context.Context, actor audit.Actor, name, line string, maxValidity time.Duration) (*HostCA, error) {
	v := &apperr.Validation{}
	if !aliasRE.MatchString(name) {
		v.Add("name", "%s", AliasRule)
	}
	if maxValidity < time.Hour || maxValidity > 5*365*24*time.Hour {
		v.Add("max_validity", "must be between 1h and 5 years")
	}
	pk, err := ParseHostKey(line)
	if err != nil {
		v.Add("public_key", "%s", err.Error())
	}
	if err := v.Err(); err != nil {
		return nil, err
	}
	id := ids.New(ids.HostCA)
	err = svc.s.W().TxNamed(ctx, "inventory.create_host_ca", func(tx *store.Tx) error {
		if err := tx.Q.InsertHostCA(ctx, db.InsertHostCAParams{
			ID: id, Name: name, PublicKey: marshalKey(pk), FingerprintSha256: ssh.FingerprintSHA256(pk),
			MaxValidityS: int64(maxValidity / time.Second), CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros(),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "a host CA with this name or key already exists")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "host_ca.created", Target: audit.Target{Type: "host_ca", ID: id},
			Details: map[string]any{"name": name, "fingerprint": ssh.FingerprintSHA256(pk), "max_validity": maxValidity.String()}})
		return err
	})
	if err != nil {
		return nil, err
	}
	r, err := svc.s.R().GetHostCA(ctx, id)
	if err != nil {
		return nil, err
	}
	return hostCAFromRow(r), nil
}

// BindHostCA trusts caID for serverID with the given required principals (caID "" unbinds).
func (svc *Service) BindHostCA(ctx context.Context, actor audit.Actor, serverID, caID string, principals []string) error {
	principals = normalizeList(principals)
	if caID != "" && len(principals) == 0 {
		return apperr.New(apperr.CodeInvalid, "at least one required certificate principal must be listed for the server")
	}
	for _, p := range principals {
		if p == "" || len(p) > 253 || strings.ContainsAny(p, " ,\t\n") {
			return apperr.New(apperr.CodeInvalid, "invalid principal %q", p)
		}
	}
	return svc.s.W().TxNamed(ctx, "inventory.bind_host_ca", func(tx *store.Tx) error {
		if _, err := tx.Q.GetServer(ctx, serverID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		if caID != "" {
			if ca, err := tx.Q.GetHostCA(ctx, caID); errors.Is(err, sql.ErrNoRows) || (err == nil && ca.State != "active") {
				return apperr.New(apperr.CodeNotFound, "active host CA not found")
			} else if err != nil {
				return err
			}
		}
		if err := tx.Q.SetServerHostCA(ctx, db.SetServerHostCAParams{
			HostCaID: sql.NullString{String: caID, Valid: caID != ""}, UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor), ID: serverID,
		}); err != nil {
			return err
		}
		if err := tx.Q.DeleteHostCAPrincipals(ctx, serverID); err != nil {
			return err
		}
		for _, p := range principals {
			if err := tx.Q.InsertHostCAPrincipal(ctx, db.InsertHostCAPrincipalParams{ServerID: serverID, Principal: p}); err != nil {
				return err
			}
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_ca.bound", Target: audit.Target{Type: "server", ID: serverID},
			Details: map[string]any{"host_ca_id": caID, "principals": principals}})
		svc.publish(tx, eventbus.TopicInventoryChanged, serverID)
		return err
	})
}

func hostCAFromRow(r db.HostCa) *HostCA {
	return &HostCA{ID: r.ID, Name: r.Name, PublicKey: r.PublicKey, Fingerprint: r.FingerprintSha256,
		MaxValidity: time.Duration(r.MaxValidityS) * time.Second, State: r.State}
}

// HostKeyError reports a destination host key that is not trusted (HP-SSH-011, HP-SRV-005).
type HostKeyError struct {
	ServerID    string
	Presented   string // fingerprint presented by the destination
	Algorithm   string
	Certificate bool
	Reason      string
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("destination host key %s (%s) is not trusted for server %s: %s", e.Presented, e.Algorithm, e.ServerID, e.Reason)
}

// Verifier is a strict host key check for one server.
type Verifier struct {
	ServerID   string
	Callback   ssh.HostKeyCallback
	Algorithms []string
}

// NewVerifier builds the host key check for a server from its active identities and bound host CA. It fails when
// the server has neither, because unknown hosts are never trusted.
func (svc *Service) NewVerifier(ctx context.Context, serverID string) (*Verifier, error) {
	srv, err := svc.GetServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	ids, err := svc.s.R().ListHostIdentities(ctx, serverID)
	if err != nil {
		return nil, err
	}
	trusted := map[string]bool{}
	var algos []string
	for _, h := range ids {
		if h.State != "active" {
			continue
		}
		trusted[h.FingerprintSha256] = true
		for _, a := range sshalg.HostKeyAlgorithmsFor(h.Algorithm) {
			if !slices.Contains(algos, a) {
				algos = append(algos, a)
			}
		}
	}
	var ca *HostCA
	if srv.HostCAID != "" {
		r, err := svc.s.R().GetHostCA(ctx, srv.HostCAID)
		if err != nil {
			return nil, err
		}
		if r.State == "active" {
			ca = hostCAFromRow(r)
			algos = append(slices.Clone(sshalg.HostCertAlgorithms), algos...)
		}
	}
	if len(trusted) == 0 && ca == nil {
		return nil, &HostKeyError{ServerID: serverID, Reason: "no active host identity or host CA is enrolled"}
	}
	clk := svc.opts.Clock
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if cert, ok := key.(*ssh.Certificate); ok {
			return checkHostCert(serverID, cert, ca, srv.Principals, clk.Now())
		}
		fp := ssh.FingerprintSHA256(key)
		if trusted[fp] {
			return nil
		}
		return &HostKeyError{ServerID: serverID, Presented: fp, Algorithm: key.Type(), Reason: "host key changed or unknown"}
	}
	return &Verifier{ServerID: serverID, Callback: cb, Algorithms: algos}, nil
}

func checkHostCert(serverID string, cert *ssh.Certificate, ca *HostCA, principals []string, now time.Time) error {
	fail := func(reason string) error {
		return &HostKeyError{ServerID: serverID, Presented: ssh.FingerprintSHA256(cert.Key), Algorithm: cert.Type(), Certificate: true, Reason: reason}
	}
	if ca == nil {
		return fail("host certificates are not trusted for this server (no host CA bound)")
	}
	if cert.CertType != ssh.HostCert {
		return fail("certificate is not a host certificate")
	}
	if ssh.FingerprintSHA256(cert.SignatureKey) != ca.Fingerprint {
		return fail("certificate not signed by the bound host CA")
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore > cert.ValidAfter &&
		time.Duration(cert.ValidBefore-cert.ValidAfter)*time.Second > ca.MaxValidity { //nolint:gosec // bounded by check above
		return fail("certificate validity exceeds the host CA's maximum")
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return fail("certificates without expiry are not accepted")
	}
	checker := &ssh.CertChecker{Clock: func() time.Time { return now }}
	var lastErr error
	for _, p := range principals {
		if lastErr = checker.CheckCert(p, cert); lastErr == nil {
			return nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no principals configured")
	}
	return fail("certificate rejected: " + lastErr.Error())
}

// errScanDone aborts a handshake after the host key has been captured.
var errScanDone = errors.New("host key captured")

// ScanHostKeys connects to a server through the egress guard and records each offered host key as a pending identity.
// Operators must confirm pending identities against an out-of-band source before they are trusted.
func (svc *Service) ScanHostKeys(ctx context.Context, actor audit.Actor, serverID string) ([]*HostIdentity, error) {
	srv, err := svc.GetServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if svc.opts.Guard == nil {
		return nil, apperr.New(apperr.CodeUnavailable, "egress policy not configured")
	}
	var found []ssh.PublicKey
	for _, algo := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512} {
		pk, err := svc.scanOne(ctx, srv, algo)
		if err != nil {
			continue // the server may not offer this algorithm
		}
		if !slices.ContainsFunc(found, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), pk.Marshal()) }) {
			found = append(found, pk)
		}
	}
	if len(found) == 0 {
		return nil, apperr.New(apperr.CodeUnavailable, "no host keys could be retrieved from %s:%d", srv.Address, srv.Port)
	}
	err = svc.s.W().TxNamed(ctx, "inventory.scan_host_keys", func(tx *store.Tx) error {
		var fps []string
		for _, pk := range found {
			fp := ssh.FingerprintSHA256(pk)
			if _, err := tx.Q.GetHostIdentityByFingerprint(ctx, db.GetHostIdentityByFingerprintParams{ServerID: serverID, FingerprintSha256: fp}); err == nil {
				continue
			}
			if err := tx.Q.InsertHostIdentity(ctx, db.InsertHostIdentityParams{
				ID: ids.New(ids.HostIdentity), ServerID: serverID, Algorithm: pk.Type(), PublicKey: marshalKey(pk), FingerprintSha256: fp,
				State: "pending", EnrolledVia: "scan", CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor),
			}); err != nil {
				return err
			}
			fps = append(fps, fp)
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.host_identity.scanned", Target: audit.Target{Type: "server", ID: serverID},
			Details: map[string]any{"new_pending": fps}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.ListHostIdentities(ctx, serverID)
}

func (svc *Service) scanOne(ctx context.Context, srv *Server, algo string) (ssh.PublicKey, error) {
	dctx, cancel := context.WithTimeout(ctx, svc.opts.DialTimeout)
	defer cancel()
	conn, err := svc.opts.Guard.Dial(dctx, srv.Address, srv.Port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(svc.opts.DialTimeout))
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		Config:            sshalg.Config(),
		User:              "hallpass-scan",
		HostKeyAlgorithms: []string{algo},
		ClientVersion:     "SSH-2.0-Hallpass",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errScanDone
		},
	}
	_, _, _, err = ssh.NewClientConn(conn, net.JoinHostPort(srv.Address, fmt.Sprint(srv.Port)), cfg)
	if captured != nil {
		if _, isCert := captured.(*ssh.Certificate); isCert {
			return nil, errors.New("certificate offered")
		}
		return captured, nil
	}
	return nil, err
}

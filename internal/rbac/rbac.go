// Package rbac is the operator permission matrix (PLAN §12.5, HP-RBAC-*). Every API operation names exactly one
// permission (OpenAPI x-permission); Authorize is the single server-side decision point. Scope-dependent checks
// (approver rules for decisions and revocations) are enforced by the domain services on top of this.
package rbac

import (
	"slices"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// Permission is a named capability.
type Permission string

// Permissions (PLAN §12.5).
const (
	DashboardView        Permission = "dashboard.view"
	InventoryRead        Permission = "inventory.read"
	InventoryAddressRead Permission = "inventory.address.read"
	InventoryWrite       Permission = "inventory.write"
	PolicyRead           Permission = "policy.read"
	PolicyWrite          Permission = "policy.write"
	CredentialsManage    Permission = "credentials.manage"
	KeysManage           Permission = "keys.manage"
	RequestsRead         Permission = "requests.read"
	RequestsReasonRead   Permission = "requests.reason.read"
	RequestsDecide       Permission = "requests.decide"
	RequestsCancel       Permission = "requests.cancel"
	GrantsRevoke         Permission = "grants.revoke"
	SessionsRead         Permission = "sessions.read"
	ActivitiesTerminate  Permission = "activities.terminate"
	RecordingPlay        Permission = "recording.play"
	RecordingExport      Permission = "recording.export"
	AuditRead            Permission = "audit.read"
	AuditVerify          Permission = "audit.verify"
	RetentionManage      Permission = "retention.manage"
	OperatorsManage      Permission = "operators.manage"
	AuthSettings         Permission = "auth.settings"
	IntegrationsManage   Permission = "integrations.manage"
	LockdownEnable       Permission = "system.lockdown.enable"
	LockdownLift         Permission = "system.lockdown.lift"
	SystemSettings       Permission = "system.settings"
	SystemRead           Permission = "system.read"
)

// Pseudo-permissions used by operations that are not role-gated.
const (
	// Public operations need no session (login, auth config, OIDC callback).
	Public Permission = "public"
	// Session operations need any full session (self-service, live events).
	Session Permission = "session"
	// Limited operations are allowed while MFA is still pending (MFA verification and enrollment).
	Limited Permission = "session.limited"
)

// Options are the configurable cells of the matrix (all off by default).
type Options struct {
	AuditorAddressRead     bool
	ApproverRecordingPlay  bool
	AuditorRecordingExport bool
	ApproversCanLockdown   bool
}

// Matrix maps roles to permissions.
type Matrix struct{ roles map[string][]Permission }

// New builds the matrix. Requirements: recent authentication and MFA flags are per operation, not per permission.
func New(o Options) *Matrix {
	all := []Permission{DashboardView, InventoryRead, RequestsRead, SessionsRead, PolicyRead}
	admin := append(slices.Clone(all), InventoryAddressRead, InventoryWrite, PolicyWrite, CredentialsManage, KeysManage, RequestsReasonRead,
		RequestsDecide, RequestsCancel, GrantsRevoke, ActivitiesTerminate, RecordingPlay, RecordingExport, AuditRead, AuditVerify, RetentionManage,
		OperatorsManage, AuthSettings, IntegrationsManage, LockdownEnable, LockdownLift, SystemSettings, SystemRead)
	approver := append(slices.Clone(all), RequestsReasonRead, RequestsDecide, RequestsCancel, GrantsRevoke, ActivitiesTerminate)
	auditor := append(slices.Clone(all), RequestsReasonRead, RecordingPlay, AuditRead, AuditVerify, SystemRead)
	viewer := slices.Clone(all)
	if o.AuditorAddressRead {
		auditor = append(auditor, InventoryAddressRead)
	}
	if o.ApproverRecordingPlay {
		approver = append(approver, RecordingPlay)
	}
	if o.AuditorRecordingExport {
		auditor = append(auditor, RecordingExport)
	}
	if o.ApproversCanLockdown {
		approver = append(approver, LockdownEnable)
	}
	return &Matrix{roles: map[string][]Permission{
		opauth.RoleAdministrator: admin, opauth.RoleApprover: approver, opauth.RoleAuditor: auditor, opauth.RoleViewer: viewer,
	}}
}

// Has reports whether any of the roles holds the permission.
func (m *Matrix) Has(roles []string, p Permission) bool {
	for _, r := range roles {
		if slices.Contains(m.roles[r], p) {
			return true
		}
	}
	return false
}

// Permissions returns the union of permissions for roles, sorted (for /me and the UI).
func (m *Matrix) Permissions(roles []string) []Permission {
	var out []Permission
	for _, r := range roles {
		for _, p := range m.roles[r] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ErrForbidden is the uniform denial (no hint about which permission was missing beyond the code).
var ErrForbidden = apperr.New(apperr.CodeForbidden, "you do not have permission for this action")

// Authorize is the single server-side check for operation permissions. It depends only on the operator's role
// assignments, never on how the operator authenticated (HP-RBAC-006). Operators without roles hold nothing
// (HP-RBAC-007).
func (m *Matrix) Authorize(p *opauth.Principal, perm Permission) error {
	switch perm {
	case Public:
		return nil
	case Limited:
		if p == nil {
			return opauth.ErrUnauthorized
		}
		return nil
	}
	if p == nil {
		return opauth.ErrUnauthorized
	}
	if p.Limited {
		return opauth.ErrMFARequired
	}
	if perm == Session {
		return nil
	}
	if !m.Has(p.Operator.Roles, perm) {
		return ErrForbidden
	}
	return nil
}

// Known reports whether perm is a defined permission or pseudo-permission (used by the spec conformance test).
func Known(perm Permission) bool {
	switch perm {
	case Public, Session, Limited:
		return true
	}
	return slices.Contains(New(Options{AuditorAddressRead: true, ApproverRecordingPlay: true, AuditorRecordingExport: true,
		ApproversCanLockdown: true}).roles[opauth.RoleAdministrator], perm)
}

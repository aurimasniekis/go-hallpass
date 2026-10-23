package rbac

import (
	"errors"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// HP-RBAC-002/004/005/007: defaults of the published matrix and its configurable cells.
func TestDefaults(t *testing.T) {
	m := New(Options{})
	cases := []struct {
		role string
		p    Permission
		want bool
	}{
		{opauth.RoleAdministrator, InventoryAddressRead, true},
		{opauth.RoleAuditor, InventoryAddressRead, false},
		{opauth.RoleApprover, InventoryAddressRead, false},
		{opauth.RoleAuditor, RecordingPlay, true},
		{opauth.RoleAdministrator, RecordingExport, true},
		{opauth.RoleAuditor, RecordingExport, false},
		{opauth.RoleApprover, RecordingPlay, false},
		{opauth.RoleApprover, GrantsRevoke, true},
		{opauth.RoleViewer, GrantsRevoke, false},
		{opauth.RoleAdministrator, RetentionManage, true},
		{opauth.RoleApprover, RetentionManage, false},
		{opauth.RoleViewer, RequestsReasonRead, false},
		{opauth.RoleApprover, LockdownEnable, false},
		{opauth.RoleViewer, DashboardView, true},
	}
	for _, c := range cases {
		if got := m.Has([]string{c.role}, c.p); got != c.want {
			t.Errorf("%s %s = %v", c.role, c.p, got)
		}
	}
	if len(m.Permissions(nil)) != 0 || m.Has(nil, DashboardView) {
		t.Fatal("no roles must mean no permissions (HP-RBAC-007)")
	}
	o := New(Options{AuditorAddressRead: true, ApproverRecordingPlay: true, AuditorRecordingExport: true, ApproversCanLockdown: true})
	for _, c := range []struct {
		role string
		p    Permission
	}{{opauth.RoleAuditor, InventoryAddressRead}, {opauth.RoleApprover, RecordingPlay}, {opauth.RoleAuditor, RecordingExport}, {opauth.RoleApprover, LockdownEnable}} {
		if !o.Has([]string{c.role}, c.p) {
			t.Errorf("option not applied: %s %s", c.role, c.p)
		}
	}
	if o.Has([]string{opauth.RoleApprover}, LockdownLift) {
		t.Fatal("approvers may never lift lockdown")
	}
}

func TestAuthorize(t *testing.T) {
	m := New(Options{})
	viewer := &opauth.Principal{Operator: &opauth.Operator{Roles: []string{opauth.RoleViewer}}}
	if m.Authorize(nil, Public) != nil || !errors.Is(m.Authorize(nil, Session), opauth.ErrUnauthorized) || !errors.Is(m.Authorize(nil, Limited), opauth.ErrUnauthorized) {
		t.Fatal("anonymous handling")
	}
	if m.Authorize(viewer, Session) != nil || m.Authorize(viewer, DashboardView) != nil || !errors.Is(m.Authorize(viewer, AuditRead), ErrForbidden) {
		t.Fatal("viewer handling")
	}
	limited := &opauth.Principal{Operator: viewer.Operator, Limited: true}
	if m.Authorize(limited, Limited) != nil || !errors.Is(m.Authorize(limited, DashboardView), opauth.ErrMFARequired) {
		t.Fatal("limited sessions may only use MFA endpoints")
	}
	if !Known(AuditRead) || !Known(Public) || Known("made.up") {
		t.Fatal("Known")
	}
}

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// Web paths that accept one-time tokens. recoveryPath is provisional until the HTTP API (WP15) and web UI (WP19)
// ship the recovery-login page; the token itself is always printed as well.
const (
	setupPath    = "/setup"
	recoveryPath = "/recover"
)

func adminCommands() *command {
	return &command{
		name:    "admin",
		summary: "first-administrator bootstrap and break-glass recovery (offline; takes the data-directory lock; needs the KEK)",
		sub: []*command{
			{name: "bootstrap", summary: "issue the one-time setup token for the first administrator", run: runAdminBootstrap},
			{name: "recover", summary: "break-glass: issue a single-use 30-minute recovery login (audited)", run: runAdminRecover},
		},
	}
}

// authService builds the operator-auth service over an offline App (the CLI holds the lock and the KEK).
func authService(a *app.App) *opauth.Service {
	return opauth.New(a.Store, a.Keyring, a.Audit, a.Bus, opauth.Options{Clock: a.Clock})
}

func tokenURL(publicURL, p, token string) string {
	return strings.TrimRight(publicURL, "/") + p + "?token=" + url.QueryEscape(token)
}

func runAdminBootstrap(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("admin bootstrap", stderr)
	path := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	token, exp, err := authService(a).IssueSetupToken(ctx)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	fmt.Fprintf(stdout, "one-time setup link (single use, expires %s); it is shown only once:\n  %s\n  token: %s\n",
		exp.UTC().Format(time.RFC3339), tokenURL(a.Cfg.PublicURL, setupPath, token), token)
	return nil
}

// runAdminRecover is the break-glass path (HP-AUTH-016, PLAN §18.16). It has no remote equivalent: it runs only
// on the host, takes the data-directory lock (the server must be stopped) and needs the KEK to open the keyring.
func runAdminRecover(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("admin recover", stderr)
	path := configFlag(fs)
	email := fs.String("email", "", "email of the operator to recover (or of the new administrator with --new-admin)")
	newAdmin := fs.Bool("new-admin", false, "create a new local administrator with --email instead of recovering an existing operator")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *email == "" {
		return &exitError{code: 2, err: errors.New("--email is required")}
	}
	norm, err := opauth.NormalizeEmail(*email)
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	var opID, newEmail string
	if *newAdmin {
		newEmail = norm
	} else {
		row, err := a.Store.R().GetOperatorByEmail(ctx, sql.NullString{String: norm, Valid: true})
		if errors.Is(err, sql.ErrNoRows) {
			return &exitError{code: 1, err: fmt.Errorf("no operator with email %s (use --new-admin to create a new administrator)", norm)}
		}
		if err != nil {
			return &exitError{code: 1, err: err}
		}
		opID = row.ID
	}
	token, exp, err := authService(a).IssueRecoveryLogin(ctx, opID, newEmail)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	fmt.Fprintf(stdout, "BREAK-GLASS recovery login for %s issued and audited (breakglass.used).\n", norm)
	fmt.Fprintf(stdout, "Single use, expires %s. It is shown only once; do not store or forward it.\n  %s\n  token: %s\n",
		exp.UTC().Format(time.RFC3339), tokenURL(a.Cfg.PublicURL, recoveryPath, token), token)
	fmt.Fprintln(stdout, "After signing in, review the audit log and rotate credentials as needed.")
	return nil
}

package app

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/sshfront"
)

// Serve runs the gateway until ctx is canceled, then drains: new connections are refused, established sessions get
// shutdown.drain_timeout to finish, and whatever remains is terminated and recorded as "shutdown" (HP-OPS-002).
// sshLn may be nil to listen on ssh.listen.
func (a *App) Serve(ctx context.Context, sshLn net.Listener) error {
	if a.Proxy == nil {
		a.NewProxy()
	}
	var err error
	if sshLn == nil {
		if sshLn, err = Listen(ctx, a.Cfg.SSH.Listen); err != nil {
			return err
		}
	}
	h := &sshfront.Handler{Access: a.Access, Engine: a.Engine, Proxy: a.Proxy, Bus: a.Bus, Log: a.Log,
		WaitDefault: a.Cfg.Access.WaitTimeoutDefault.D(), WaitMax: a.Cfg.Access.WaitTimeoutMax.D()}
	srv := sshfront.New(sshfront.Options{Config: a.Cfg.SSH, Agents: a.Agents, Access: a.Access, Audit: a.Audit, Store: a.Store,
		Hosts: a.Credentials, Handler: h, Logger: a.Log})
	h.Deny = srv.AuditDenied

	bgCtx, stopBG := context.WithCancel(context.WithoutCancel(ctx))
	waitBG := a.RunBackground(bgCtx)
	a.Log.Info("hallpass serving", slog.String("ssh", sshLn.Addr().String()), slog.String("boot_id", a.BootID))

	serveErr := srv.Serve(ctx, sshLn)

	drain := a.Cfg.Shutdown.DrainTimeout.D()
	a.Log.Info("draining", slog.Int("connections", srv.ActiveConnections()), slog.Duration("timeout", drain))
	deadline := time.Now().Add(drain)
	for srv.ActiveConnections() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := a.Enforcer.Count(); n > 0 {
		a.Log.Warn("terminating sessions still active after drain", slog.Int("channels", n))
		a.Enforcer.TerminateAll("shutdown")
	}
	srv.Shutdown()
	srv.Wait()
	stopBG()
	waitBG()
	a.Log.Info("hallpass stopped")
	return serveErr
}

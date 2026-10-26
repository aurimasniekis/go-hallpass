package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"
	"github.com/nats-io/nats.go"

	"github.com/aurimasniekis/go-hallpass/internal/events"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
)

// relayEvents connects to Pulse (retrying while it is unreachable) and publishes outbox events until ctx ends
// (ADR-0057). Pulse being down never affects HallPass: events wait in the outbox.
func (a *App) relayEvents(ctx context.Context) {
	pc := a.Cfg.Events.Pulse
	log := obs.Component(a.Log, "events")
	opts := []pulse.Option{pulse.WithCredsFile(pc.CredsFile), pulse.WithSource(pc.Source), pulse.WithName("hallpass"),
		pulse.WithNATSOptions(
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				if err != nil { // nil: closed on shutdown
					log.Warn("event relay disconnected from Pulse; events wait in the outbox", obs.Err(err))
				}
			}),
			nats.ReconnectHandler(func(*nats.Conn) { log.Info("event relay reconnected to Pulse") }),
		)}
	if pc.CAFile != "" {
		opts = append(opts, pulse.WithCAFile(pc.CAFile))
	}
	for {
		c, err := pulse.Connect(pc.URL, opts...)
		if err == nil {
			log.Info("event relay connected to Pulse", slog.String("url.full", pc.URL))
			r := &events.Relay{Store: a.Store, Pub: c, Clock: a.Clock, Metrics: a.Metrics, Log: log}
			r.Run(ctx, 2*time.Second)
			c.Close()
			return
		}
		log.Warn("event relay cannot connect to Pulse; events wait in the outbox", slog.String("url.full", pc.URL), obs.Err(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

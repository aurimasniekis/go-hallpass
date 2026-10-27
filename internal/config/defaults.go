package config

import "time"

// DefaultDurationPresets are the configurable approval duration presets.
var DefaultDurationPresets = []time.Duration{
	5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 24 * time.Hour,
}

// Default returns a configuration with every default applied.
func Default() *Config {
	presets := make([]Duration, len(DefaultDurationPresets))
	for i, p := range DefaultDurationPresets {
		presets[i] = Duration(p)
	}
	return &Config{
		Mode:    ModeProduction,
		DataDir: "/var/lib/hallpass",
		KEK:     KEKConfig{Source: "file", File: "/etc/hallpass/kek"},
		SSH: SSHConfig{
			Listen:                  ":2222",
			MaxUnauthenticated:      256,
			MaxUnauthenticatedPerIP: 16,
			HandshakeTimeout:        Duration(10 * time.Second),
			MaxAuthTries:            6,
			MaxConnectionsPerAgent:  32,
			MaxChannelsPerConn:      16,
			KeepaliveInterval:       Duration(30 * time.Second),
			KeepaliveMaxMissed:      3,
			IdleTimeout:             Duration(30 * time.Minute),
			DialTimeout:             Duration(10 * time.Second),
			EnvAllow:                []string{"TERM", "LANG", "LC_*"},
			Ban: SSHBanConfig{Enabled: true, MaxFailures: 10, Window: Duration(10 * time.Minute), Duration: Duration(15 * time.Minute),
				MaxDuration: Duration(24 * time.Hour)},
		},
		HTTP:     HTTPConfig{Listen: ":8080"},
		Console:  ConsoleConfig{Terminal: true},
		Events:   EventsConfig{Pulse: PulseConfig{Source: "hallpass"}},
		APIProxy: APIProxyConfig{Enabled: true, AllowCIDRs: []string{"0.0.0.0/0", "::/0"}},
		Log:      LogConfig{Level: "info", Format: "json"},
		Storage: StorageConfig{
			MinFreeBytes:          2 << 30,
			MinFreePercent:        5,
			AlertPercent:          []int{80, 90},
			PreMigrationSnapshots: 3,
		},
		Recording: RecordingConfig{
			Durability:       "group",
			FlushInterval:    Duration(250 * time.Millisecond),
			SegmentMaxBytes:  64 << 20,
			SegmentMaxAge:    Duration(time.Hour),
			QueueRecords:     1024,
			QueueBytes:       1 << 20,
			BlockTimeout:     Duration(10 * time.Second),
			DefaultRetention: Duration(90 * 24 * time.Hour),
		},
		Access: AccessConfig{
			WaitTimeoutDefault:    Duration(120 * time.Second),
			WaitTimeoutMax:        Duration(15 * time.Minute),
			PendingExpiry:         Duration(30 * time.Minute),
			DurationPresets:       presets,
			MaxGrantDuration:      Duration(24 * time.Hour),
			RequestsPerAgentHour:  30,
			MaxPendingPerAgent:    10,
			EnforcementTick:       Duration(time.Second),
			MinRemainingToConnect: Duration(2 * time.Second),
		},
		Auth: AuthConfig{
			SessionIdleTimeout:     Duration(30 * time.Minute),
			SessionAbsoluteTimeout: Duration(12 * time.Hour),
			ReauthWindow:           Duration(5 * time.Minute),
			PasswordMinBytes:       12,
		},
		Telemetry: TelemetryConfig{Prometheus: true},
		Shutdown:  ShutdownConfig{DrainTimeout: Duration(30 * time.Second)},
	}
}

// Package config loads and validates HallPass configuration (HP-OPS-013).
//
// Configuration comes from a YAML file plus HALLPASS_* environment overrides. Unknown keys are rejected.
// The runtime mode is "production" unless explicitly set to "development"; development-only features are
// rejected in production.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Mode is the runtime mode.
type Mode string

// Runtime modes.
const (
	ModeProduction  Mode = "production"
	ModeDevelopment Mode = "development"
)

// Duration is a time.Duration that unmarshals from Go duration strings ("30s", "15m").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string like \"30s\": %w", n.Line, err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config is the complete HallPass configuration.
type Config struct {
	Mode      Mode            `yaml:"mode"`
	DataDir   string          `yaml:"data_dir"`
	PublicURL string          `yaml:"public_url"`
	KEK       KEKConfig       `yaml:"kek"`
	SSH       SSHConfig       `yaml:"ssh"`
	HTTP      HTTPConfig      `yaml:"http"`
	Log       LogConfig       `yaml:"log"`
	Storage   StorageConfig   `yaml:"storage"`
	Recording RecordingConfig `yaml:"recording"`
	Egress    EgressConfig    `yaml:"egress"`
	Access    AccessConfig    `yaml:"access"`
	Auth      AuthConfig      `yaml:"auth"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Shutdown  ShutdownConfig  `yaml:"shutdown"`
	RBAC      RBACConfig      `yaml:"rbac"`
	Console   ConsoleConfig   `yaml:"console"`
	Dev       DevConfig       `yaml:"dev"`
}

// KEKConfig locates the master key-encryption key (HP-CRY-001).
type KEKConfig struct {
	// Source is "file" (default) or "env" (reads base64 from HALLPASS_KEK; discouraged).
	Source string `yaml:"source"`
	File   string `yaml:"file"`
}

// SSHConfig configures the agent-facing SSH listener and both SSH legs (HP-SSH-012, HP-SSH-013).
type SSHConfig struct {
	Listen                  string       `yaml:"listen"`
	MaxUnauthenticated      int          `yaml:"max_unauthenticated"`
	MaxUnauthenticatedPerIP int          `yaml:"max_unauthenticated_per_ip"`
	HandshakeTimeout        Duration     `yaml:"handshake_timeout"`
	MaxAuthTries            int          `yaml:"max_auth_tries"`
	MaxConnectionsPerAgent  int          `yaml:"max_connections_per_agent"`
	MaxChannelsPerConn      int          `yaml:"max_channels_per_connection"`
	KeepaliveInterval       Duration     `yaml:"keepalive_interval"`
	KeepaliveMaxMissed      int          `yaml:"keepalive_max_missed"`
	IdleTimeout             Duration     `yaml:"idle_timeout"`
	DialTimeout             Duration     `yaml:"dial_timeout"`
	EnvAllow                []string     `yaml:"env_allow"`
	Ban                     SSHBanConfig `yaml:"ban"`
}

// SSHBanConfig configures fail2ban-style bans of SSH sources after repeated failed authentication (HP-SSH-026).
type SSHBanConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxFailures failed authentications from one source (IPv4 address or IPv6 /64) within Window trigger a ban.
	MaxFailures int      `yaml:"max_failures"`
	Window      Duration `yaml:"window"`
	// Duration is the first ban's length; it doubles for each further ban of the source within 7 days, up to
	// MaxDuration.
	Duration    Duration `yaml:"duration"`
	MaxDuration Duration `yaml:"max_duration"`
	// AllowCIDRs are never banned (for example agent subnets behind shared NAT).
	AllowCIDRs []string `yaml:"allow_cidrs"`
}

// HTTPConfig configures the web/API listener.
type HTTPConfig struct {
	Listen         string   `yaml:"listen"`
	TLSCertFile    string   `yaml:"tls_cert_file"`
	TLSKeyFile     string   `yaml:"tls_key_file"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	MetricsListen  string   `yaml:"metrics_listen"`
}

// LogConfig configures structured logging (HP-OBS-001).
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	// AuditFile, if set, receives every committed audit record as one JSON line (mode 0600, append) for SIEM
	// ingestion (HP-OBS-005). The database hash chain stays authoritative.
	AuditFile string `yaml:"audit_file"`
}

// StorageConfig configures storage safety thresholds (HP-OPS-006, HP-DB-009).
type StorageConfig struct {
	MinFreeBytes   int64 `yaml:"min_free_bytes"`
	MinFreePercent int   `yaml:"min_free_percent"`
	AlertPercent   []int `yaml:"alert_percent"`
	// AllowNetworkFS overrides the network-filesystem refusal (HP-DB-007). Never set in production.
	AllowNetworkFS bool `yaml:"allow_network_fs"`
	// PreMigrationSnapshots is how many pre-migration snapshots are kept.
	PreMigrationSnapshots int `yaml:"pre_migration_snapshots"`
}

// RecordingConfig configures the recorder (HP-REC-008).
type RecordingConfig struct {
	// Durability is "group" (fsync at most every FlushInterval) or "strict" (fsync before forwarding).
	Durability       string   `yaml:"durability"`
	FlushInterval    Duration `yaml:"flush_interval"`
	SegmentMaxBytes  int64    `yaml:"segment_max_bytes"`
	SegmentMaxAge    Duration `yaml:"segment_max_age"`
	QueueRecords     int      `yaml:"queue_records"`
	QueueBytes       int      `yaml:"queue_bytes"`
	BlockTimeout     Duration `yaml:"block_timeout"`
	DefaultRetention Duration `yaml:"default_retention"`
	// RetentionClasses overrides the retention per role retention class: entries "class=duration", e.g.
	// "sensitive=8760h" (HP-REC-013). Classes without an entry use DefaultRetention.
	RetentionClasses []string `yaml:"retention_classes"`
}

// EgressConfig configures the outbound destination guard (HP-SRV-009).
type EgressConfig struct {
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// AllowSpecialCIDRs explicitly re-allows ranges denied by default (loopback, link-local, metadata).
	AllowSpecialCIDRs []string `yaml:"allow_special_cidrs"`
	// SourceAddresses are the gateway's egress addresses as destinations see them; used in suggested
	// authorized_keys from= restrictions and firewall guidance (HP-KEY-002).
	SourceAddresses []string `yaml:"source_addresses"`
}

// AccessConfig configures request, wait and grant timing (HP-REQ-004, HP-REQ-005, HP-REQ-007).
type AccessConfig struct {
	WaitTimeoutDefault    Duration   `yaml:"wait_timeout_default"`
	WaitTimeoutMax        Duration   `yaml:"wait_timeout_max"`
	PendingExpiry         Duration   `yaml:"pending_expiry"`
	DurationPresets       []Duration `yaml:"duration_presets"`
	MaxGrantDuration      Duration   `yaml:"max_grant_duration"`
	RequestsPerAgentHour  int        `yaml:"requests_per_agent_hour"`
	MaxPendingPerAgent    int        `yaml:"max_pending_per_agent"`
	EnforcementTick       Duration   `yaml:"enforcement_tick"`
	MinRemainingToConnect Duration   `yaml:"min_remaining_to_connect"`
}

// AuthConfig configures operator authentication defaults (HP-AUTH-*).
type AuthConfig struct {
	SessionIdleTimeout     Duration `yaml:"session_idle_timeout"`
	SessionAbsoluteTimeout Duration `yaml:"session_absolute_timeout"`
	ReauthWindow           Duration `yaml:"reauth_window"`
	PasswordMinBytes       int      `yaml:"password_min_bytes"`
}

// TelemetryConfig configures OpenTelemetry export (HP-OBS-004).
type TelemetryConfig struct {
	OTLPEndpoint string `yaml:"otlp_endpoint"`
	Prometheus   bool   `yaml:"prometheus"`
}

// ShutdownConfig configures graceful shutdown (HP-OPS-002).
type ShutdownConfig struct {
	DrainTimeout Duration `yaml:"drain_timeout"`
}

// ConsoleConfig controls web console features (ADR-0055).
type ConsoleConfig struct {
	// Terminal lets administrators open recorded terminals on servers from the console (default true).
	Terminal bool `yaml:"terminal"`
}

// RBACConfig sets the configurable cells of the operator permission matrix (PLAN §12.5); all default to false.
type RBACConfig struct {
	AuditorAddressRead     bool `yaml:"auditor_address_read"`
	ApproverRecordingPlay  bool `yaml:"approver_recording_play"`
	AuditorRecordingExport bool `yaml:"auditor_recording_export"`
	ApproversCanLockdown   bool `yaml:"approvers_can_lockdown"`
}

// DevConfig holds development-only features. Any of them in production mode is a validation error (HP-AUTH-017).
type DevConfig struct {
	InsecureHTTP bool   `yaml:"insecure_http"`
	Auth         bool   `yaml:"auth"`
	SeedFile     string `yaml:"seed_file"`
}

// Load reads path (if non-empty), applies defaults, environment overrides from environ and validates.
func Load(path string, environ []string) (*Config, error) {
	cfg := Default()
	if path != "" {
		f, err := os.Open(path) //nolint:gosec // operator-supplied config path
		if err != nil {
			return nil, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		if err := decode(f, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if err := applyEnv(cfg, environ); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decode(r io.Reader, cfg *Config) error {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config must contain a single YAML document")
	}
	return nil
}

// IsProduction reports whether the configuration runs in production mode.
func (c *Config) IsProduction() bool { return c.Mode != ModeDevelopment }

// RetentionFor returns the retention of a role retention class (DefaultRetention when the class has no entry).
func (r RecordingConfig) RetentionFor(class string) time.Duration {
	for _, e := range r.RetentionClasses {
		name, val, _ := strings.Cut(e, "=")
		if strings.TrimSpace(name) == class {
			if d, err := time.ParseDuration(strings.TrimSpace(val)); err == nil {
				return d
			}
		}
	}
	return r.DefaultRetention.D()
}

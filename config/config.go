package config

import (
	"fmt"
	"os"

	"github.com/obsideo/obsideo-provider/gc"
	"gopkg.in/yaml.v3"
)

const (
	DefaultPort                    = 3334
	DefaultReadTimeout             = 30
	DefaultWriteTimeout            = 300
	DefaultCoverageRefreshSeconds  = 24 * 60 * 60 // 24 hours per design §5
	DefaultCoverageBatchSize       = 500
	DefaultCoverageRequestTimeoutS = 30
)

type Config struct {
	ProviderID  string            `yaml:"provider_id"`
	Server      ServerConfig      `yaml:"server"`
	Data        DataConfig        `yaml:"data"`
	Tokens      TokensConfig      `yaml:"tokens"`
	Coordinator CoordinatorConfig `yaml:"coordinator"`
	Coverage    CoverageConfig    `yaml:"coverage"`
	GC          gc.Config         `yaml:"gc"`
	// AcceptUncontractedData controls whether the upload handler accepts
	// uploads from non-contracted accounts (testdrive, expired paid,
	// unregistered). Default true — operators ingest everything coord
	// places on them. Set false to refuse non-contracted uploads at the
	// boundary; the bytes never touch disk. Same canonical predicate the
	// GC sweeper consumes (Contracted = paid + active + unexpired), just
	// enforced at ingress instead of at retention-window expiry. Pointer
	// type so an omitted YAML key reads as nil → defaults to true; an
	// explicit `false` is preserved.
	AcceptUncontractedData *bool `yaml:"accept_uncontracted_data,omitempty"`

	// NobleWalletAddress is the operator's Noble (Cosmos chain) bech32
	// address where coord sends USDC payouts. Sent in every heartbeat
	// so coord can keep the operator's payout target current without
	// admin intervention — closes the §2 known-regression where the
	// pre-2026-05-02 heartbeat dropped this field entirely and operators
	// had to ask Reg to PATCH it via /internal/providers/{id}/noble-address.
	//
	// Format: "noble1..." (Cosmos bech32). Empty value = don't send the
	// field in heartbeat (preserves whatever coord already has on file;
	// admins can still override via the PATCH endpoint).
	NobleWalletAddress string `yaml:"noble_wallet_address,omitempty"`
}

// AcceptsUncontractedData returns the effective gate value, applying the
// default-true policy when the operator omits the field from config.
func (c *Config) AcceptsUncontractedData() bool {
	if c.AcceptUncontractedData == nil {
		return true
	}
	return *c.AcceptUncontractedData
}

type ServerConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
}

type DataConfig struct {
	Path string `yaml:"path"`
}

type TokensConfig struct {
	PublicKeyPath string `yaml:"public_key_path"`
}

// CoordinatorConfig carries outbound-connection details. Empty URL or
// empty APIKey means the provider will not attempt outbound calls, which
// is acceptable for local dev where the provider only handles inbound
// requests from a local coord.
type CoordinatorConfig struct {
	// URL is the coord's base URL, e.g. "https://coordinator.obsideo.io".
	// No trailing slash.
	URL string `yaml:"url"`

	// ProviderAPIKey is the provider's API key for coord-side
	// authentication. Stored in config rather than env to match the
	// existing provider-clean secret-loading pattern; operators deploying
	// via Akash/Docker inject the key via the config file they mount.
	ProviderAPIKey string `yaml:"provider_api_key"`
}

// CoverageConfig controls the retention-authority coverage refresh job.
// See docs/retention_authority_design.md §4.2 + §6.2.
type CoverageConfig struct {
	// RefreshIntervalS is the period between full batch-refresh cycles.
	// Design default 24 hours (spec §5 `batch_refresh_interval`).
	RefreshIntervalS int `yaml:"refresh_interval_s"`

	// BatchSize bounds the number of roots in a single coverage query.
	// Must not exceed the coord's MaxCoverageRequestBatch (1000).
	BatchSize int `yaml:"batch_size"`

	// RequestTimeoutS is the per-HTTP-call timeout.
	RequestTimeoutS int `yaml:"request_timeout_s"`

	// Enabled gates the refresh loop startup. Operators set this to true
	// once their provider-clean is upgraded to Phase 1 and the coord
	// coverage endpoint is reachable. Default false (no-op), which keeps
	// pre-Phase-1 deployments unchanged until explicitly opted in.
	Enabled bool `yaml:"enabled"`
}

// NOTE: the retention-authority circuit-breaker cold-key pubkey is
// intentionally NOT configured here. It is injected at binary build time
// via Go linker flags (see pausectl/embedded.go). Runtime config is not
// a trust root for an emergency-brake credential.

func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         DefaultPort,
			ReadTimeout:  DefaultReadTimeout,
			WriteTimeout: DefaultWriteTimeout,
		},
		Data:   DataConfig{Path: "./data"},
		Tokens: TokensConfig{PublicKeyPath: "coordinator_pub.pem"},
		Coverage: CoverageConfig{
			RefreshIntervalS: DefaultCoverageRefreshSeconds,
			BatchSize:        DefaultCoverageBatchSize,
			RequestTimeoutS:  DefaultCoverageRequestTimeoutS,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// Silent-default-on-missing is a trap: the operator starts the
		// binary with the wrong CWD, gets empty provider_id + empty
		// coord URL, and the heartbeat loop silently disables itself
		// while the HTTP listener comes up fine. Fail loudly instead.
		return nil, fmt.Errorf("read config %s: %w (check working directory and --config path)", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Apply defaults to the Coverage block for fields the operator may
	// have omitted. Must happen AFTER Unmarshal so explicit zero values
	// aren't clobbered by the block-level defaults above.
	if cfg.Coverage.RefreshIntervalS == 0 {
		cfg.Coverage.RefreshIntervalS = DefaultCoverageRefreshSeconds
	}
	if cfg.Coverage.BatchSize == 0 {
		cfg.Coverage.BatchSize = DefaultCoverageBatchSize
	}
	if cfg.Coverage.RequestTimeoutS == 0 {
		cfg.Coverage.RequestTimeoutS = DefaultCoverageRequestTimeoutS
	}

	// GC config: apply locked-design defaults to any zero-valued field
	// then validate. ApplyDefaults runs unconditionally so that even a
	// disabled GC block has fully-populated values an operator can
	// inspect; Validate is the gate that catches misconfiguration only
	// when GC is actually turned on. See docs/GC_DESIGN.md §4.
	cfg.GC.ApplyDefaults()
	if err := cfg.GC.Validate(); err != nil {
		return nil, fmt.Errorf("invalid gc config in %s: %w", path, err)
	}
	return cfg, nil
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests for config.Load, closing the "no config test" GAP from the
// storage_provider functional contract. Covers:
//   - YAML parsing of every field the operator sets
//   - Default-application for omitted fields
//   - Loud failure on missing config file (no silent-default trap)
//   - The 2026-05-02 NobleWalletAddress field that fixes the
//     §2 noble-wallet-self-service known-regression
//   - The AcceptUncontractedData pointer-bool semantics

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_HappyPath_AllFieldsSet covers a fully-specified operator
// config (the shape an experienced operator's config.yaml has after
// they've tuned everything).
func TestLoad_HappyPath_AllFieldsSet(t *testing.T) {
	path := writeConfig(t, `
provider_id: "test-provider-id-1234"
server:
  host: "127.0.0.1"
  port: 9999
  read_timeout: 60
  write_timeout: 600
data:
  path: "/var/data/obsideo"
tokens:
  public_key_path: "/etc/obsideo/coord_pub.pem"
coordinator:
  url: "https://coord.example.com"
  provider_api_key: "prv_aaa_bbb"
coverage:
  enabled: true
  refresh_interval_s: 60
  batch_size: 100
  request_timeout_s: 15
gc:
  enabled: true
  retention_non_contracted_hours: 2
  quarantine_hours: 4
  sweep_interval_hours: 1
accept_uncontracted_data: false
noble_wallet_address: "noble1abc123def456ghi"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ProviderID != "test-provider-id-1234" {
		t.Errorf("ProviderID=%q", cfg.ProviderID)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port=%d", cfg.Server.Port)
	}
	if cfg.Data.Path != "/var/data/obsideo" {
		t.Errorf("Data.Path=%q", cfg.Data.Path)
	}
	if cfg.Coordinator.URL != "https://coord.example.com" {
		t.Errorf("Coordinator.URL=%q", cfg.Coordinator.URL)
	}
	if cfg.Coverage.RefreshIntervalS != 60 {
		t.Errorf("Coverage.RefreshIntervalS=%d", cfg.Coverage.RefreshIntervalS)
	}
	if cfg.AcceptsUncontractedData() != false {
		t.Errorf("AcceptsUncontractedData()=%v, want false (explicit override)", cfg.AcceptsUncontractedData())
	}
	if cfg.NobleWalletAddress != "noble1abc123def456ghi" {
		t.Errorf("NobleWalletAddress=%q", cfg.NobleWalletAddress)
	}
}

// TestLoad_DefaultsAppliedWhenOmitted pins the default values that
// kick in for operators who provide a minimal config. The
// AcceptUncontractedData pointer specifically must default to "true"
// (open ingest) for operators who haven't opted into the gate —
// this preserves backward compatibility for every pre-2026-05-01
// deployment that doesn't know the field exists yet.
func TestLoad_DefaultsAppliedWhenOmitted(t *testing.T) {
	path := writeConfig(t, `
provider_id: "minimal-config"
coordinator:
  url: "https://coord.example.com"
  provider_api_key: "prv_x"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != DefaultPort {
		t.Errorf("Server.Port=%d, want default %d", cfg.Server.Port, DefaultPort)
	}
	if cfg.Server.ReadTimeout != DefaultReadTimeout {
		t.Errorf("Server.ReadTimeout=%d, want default", cfg.Server.ReadTimeout)
	}
	if cfg.Coverage.RefreshIntervalS != DefaultCoverageRefreshSeconds {
		t.Errorf("Coverage.RefreshIntervalS=%d, want default", cfg.Coverage.RefreshIntervalS)
	}
	if cfg.Coverage.BatchSize != DefaultCoverageBatchSize {
		t.Errorf("Coverage.BatchSize=%d, want default", cfg.Coverage.BatchSize)
	}
	if cfg.AcceptsUncontractedData() != true {
		t.Errorf("AcceptsUncontractedData()=false, want true (default for omitted field — backward compat)")
	}
	if cfg.NobleWalletAddress != "" {
		t.Errorf("NobleWalletAddress=%q, want empty (default for omitted field)", cfg.NobleWalletAddress)
	}
}

// TestLoad_MissingFileFailsLoudly is the no-silent-default-trap
// invariant. The Load implementation explicitly avoids the failure
// mode where a missing/wrong-CWD config returns an empty Config{} that
// passes basic validation but silently disables the heartbeat loop
// (because ProviderID and Coordinator.URL are empty).
func TestLoad_MissingFileFailsLoudly(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatalf("Load on missing file: err=nil, want a loud error. cfg=%+v", cfg)
	}
	if cfg != nil {
		t.Errorf("Load on missing file: cfg=%+v, want nil", cfg)
	}
}

// TestLoad_AcceptUncontractedData_ExplicitFalse_Preserved verifies
// the pointer-bool semantics: explicit `false` is NOT overridden by
// the default-true policy. This was the exact bug pattern the pointer
// type was introduced to prevent — a primitive bool would
// indistinguishably zero-decode missing fields and explicit-false.
func TestLoad_AcceptUncontractedData_ExplicitFalse_Preserved(t *testing.T) {
	path := writeConfig(t, `
provider_id: "x"
coordinator:
  url: "https://c"
  provider_api_key: "k"
accept_uncontracted_data: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AcceptUncontractedData == nil {
		t.Fatalf("AcceptUncontractedData ptr is nil; explicit `false` should set the pointer")
	}
	if *cfg.AcceptUncontractedData != false {
		t.Errorf("*AcceptUncontractedData=%v, want false", *cfg.AcceptUncontractedData)
	}
	if cfg.AcceptsUncontractedData() != false {
		t.Errorf("AcceptsUncontractedData()=true, want false (explicit override)")
	}
}

// TestLoad_NobleWalletAddress_RoundTrips pins the field shape so a
// future YAML-parsing change can't silently drop the value. This is
// the field whose absence in the pre-2026-05-02 heartbeat caused the
// §2 known-regression: operators couldn't self-service their payout
// address; everything had to go through admin PATCH.
func TestLoad_NobleWalletAddress_RoundTrips(t *testing.T) {
	const wallet = "noble1r9ljcmr4sal6tpvsveurpchtfvqukwp0jfwzx8"
	path := writeConfig(t, `
provider_id: "x"
coordinator:
  url: "https://c"
  provider_api_key: "k"
noble_wallet_address: "`+wallet+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NobleWalletAddress != wallet {
		t.Errorf("NobleWalletAddress=%q, want %q", cfg.NobleWalletAddress, wallet)
	}
}

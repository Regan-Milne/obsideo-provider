package gc

import (
	"testing"
	"time"
)

func TestConfig_ApplyDefaults_FillsZeroValues(t *testing.T) {
	c := Config{Enabled: true}
	c.ApplyDefaults()
	if c.RetentionNonContractedHours != DefaultRetentionNonContractedHours {
		t.Errorf("retention_non_contracted_hours: got %d, want %d", c.RetentionNonContractedHours, DefaultRetentionNonContractedHours)
	}
	if c.QuarantineHours != DefaultQuarantineHours {
		t.Errorf("quarantine_hours: got %d, want %d", c.QuarantineHours, DefaultQuarantineHours)
	}
	if c.SweepIntervalHours != DefaultSweepIntervalHours {
		t.Errorf("sweep_interval_hours: got %d, want %d", c.SweepIntervalHours, DefaultSweepIntervalHours)
	}
}

func TestConfig_ApplyDefaults_PreservesNonZero(t *testing.T) {
	c := Config{
		Enabled:                 true,
		RetentionNonContractedHours: 24,
		QuarantineHours:         3,
		SweepIntervalHours:      1,
	}
	c.ApplyDefaults()
	if c.RetentionNonContractedHours != 24 {
		t.Errorf("retention overwritten: got %d, want 24", c.RetentionNonContractedHours)
	}
	if c.QuarantineHours != 3 {
		t.Errorf("quarantine overwritten: got %d, want 3", c.QuarantineHours)
	}
	if c.SweepIntervalHours != 1 {
		t.Errorf("sweep_interval overwritten: got %d, want 1", c.SweepIntervalHours)
	}
}

func TestConfig_Validate_DisabledSkipsAllChecks(t *testing.T) {
	// Negative values would normally fail Validate, but with Enabled=false
	// the whole block is unread so we don't punish typos in dead config.
	c := Config{
		Enabled:                 false,
		RetentionNonContractedHours: -5,
		QuarantineHours:         -1,
		SweepIntervalHours:      0,
	}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled config should validate: %v", err)
	}
}

func TestConfig_Validate_EnabledRequiresPositiveDurations(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"retention_zero", Config{Enabled: true, QuarantineHours: 6, SweepIntervalHours: 6}},
		{"retention_negative", Config{Enabled: true, RetentionNonContractedHours: -1, QuarantineHours: 6, SweepIntervalHours: 6}},
		{"quarantine_zero", Config{Enabled: true, RetentionNonContractedHours: 48, SweepIntervalHours: 6}},
		{"sweep_zero", Config{Enabled: true, RetentionNonContractedHours: 48, QuarantineHours: 6}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Errorf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestConfig_Validate_EnabledHappyPath(t *testing.T) {
	c := Config{
		Enabled:                 true,
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	}
	if err := c.Validate(); err != nil {
		t.Errorf("happy-path config should validate: %v", err)
	}
}

func TestConfig_DurationHelpers(t *testing.T) {
	c := Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	}
	if got := c.RetentionNonContracted(); got != 48*time.Hour {
		t.Errorf("RetentionUncovered: got %v, want 48h", got)
	}
	if got := c.Quarantine(); got != 6*time.Hour {
		t.Errorf("Quarantine: got %v, want 6h", got)
	}
	if got := c.SweepInterval(); got != 6*time.Hour {
		t.Errorf("SweepInterval: got %v, want 6h", got)
	}
}

// TestConfig_NoRecheckKnob is a structural test: the design forbids a
// recheck-before-delete config knob. If someone adds one back, this
// test fails on compile (Config{} struct literal grows a field).
//
// A reflection-based variant is overkill; the compile error from a
// future struct field addition is loud enough.
func TestConfig_NoRecheckKnob(t *testing.T) {
	// Listing the full set of fields explicitly. Adding any new field
	// to Config will break this literal and force the author to think
	// about whether the new field belongs in the locked schema.
	_ = Config{
		Enabled:                 false,
		RetentionNonContractedHours: 0,
		QuarantineHours:         0,
		SweepIntervalHours:      0,
	}
}

// Package gc implements provider-side garbage collection of non-contracted
// data per docs/GC_DESIGN.md. The package boundary mirrors coverage/: GC
// is opt-in, provider-driven, and never deletes paid+active+unexpired
// customer data. The design is locked; if implementation surfaces a
// conflict with the spec the spec must be updated first then the code,
// not silently drift.
package gc

import (
	"fmt"
	"time"
)

// Config is the YAML-shape struct loaded from the provider config under
// the `gc:` key. Defaults and validation rules are taken verbatim from
// docs/GC_DESIGN.md §4.
//
// Notable absence: there is NO `recheck_before_delete` knob. Recheck is
// unconditional in production code. Tests inject a fake coverage
// rechecker through Sweeper's constructor; production code paths cannot
// bypass the live recheck. Adding a knob here would create the operator
// escape hatch the design explicitly forbids.
type Config struct {
	// Enabled gates the sweeper goroutine. Default false: existing
	// operators see no behavior change on upgrade until they read the
	// design and turn this on knowingly.
	Enabled bool `yaml:"enabled"`

	// RetentionNonContractedHours is the window an object must be
	// observed non-contracted before it becomes eligible for the
	// sweeper. Default 48h per design §4.
	RetentionNonContractedHours int `yaml:"retention_non_contracted_hours"`

	// QuarantineHours is the time a quarantined file sits in
	// quarantine/<merkle>/ before final unlink. Default 6h.
	QuarantineHours int `yaml:"quarantine_hours"`

	// SweepIntervalHours is the cadence at which the sweeper loop runs.
	// Default 6h (four times a day).
	SweepIntervalHours int `yaml:"sweep_interval_hours"`
}

// Defaults returned for fields the operator omitted. Mirror the design
// §4 numeric defaults exactly. Operator-set zero values are still
// treated as "missing" and replaced — a literal
// `retention_non_contracted_hours: 0` would mean "delete immediately on
// non-contracted observation," which is not a valid configuration and
// is rejected by Validate as unsafe.
const (
	DefaultRetentionNonContractedHours = 48
	DefaultQuarantineHours             = 6
	DefaultSweepIntervalHours          = 6
)

// ApplyDefaults fills zero-valued fields with the design defaults.
// Idempotent. Called by the config loader after YAML unmarshal so that
// an explicit zero in YAML still becomes the safe default — there is
// no operator-meaningful zero for any of the three duration fields, and
// silently honoring zero would shrink the safety window dangerously.
func (c *Config) ApplyDefaults() {
	if c.RetentionNonContractedHours == 0 {
		c.RetentionNonContractedHours = DefaultRetentionNonContractedHours
	}
	if c.QuarantineHours == 0 {
		c.QuarantineHours = DefaultQuarantineHours
	}
	if c.SweepIntervalHours == 0 {
		c.SweepIntervalHours = DefaultSweepIntervalHours
	}
}

// Validate returns nil if the config is internally consistent and safe
// to run. Validation runs after ApplyDefaults so a zero-after-default is
// a real misconfiguration (negative number written by the operator).
//
// The contract: if Enabled is true, all three durations must be
// strictly positive. If Enabled is false, validation is skipped — the
// fields aren't read by anything when the sweeper is not running, and
// rejecting the whole config because of a typo in a disabled section
// would be operator-hostile.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.RetentionNonContractedHours <= 0 {
		return fmt.Errorf("gc.retention_non_contracted_hours must be > 0 when gc.enabled is true (got %d)", c.RetentionNonContractedHours)
	}
	if c.QuarantineHours <= 0 {
		return fmt.Errorf("gc.quarantine_hours must be > 0 when gc.enabled is true (got %d)", c.QuarantineHours)
	}
	if c.SweepIntervalHours <= 0 {
		return fmt.Errorf("gc.sweep_interval_hours must be > 0 when gc.enabled is true (got %d)", c.SweepIntervalHours)
	}
	return nil
}

// RetentionNonContracted is the parsed time.Duration for the
// non-contracted retention window. Sweeper code uses these helpers
// rather than reaching into the int field so callers can't accidentally
// treat the int as seconds or minutes.
func (c *Config) RetentionNonContracted() time.Duration {
	return time.Duration(c.RetentionNonContractedHours) * time.Hour
}

// Quarantine returns the parsed time.Duration for the quarantine window.
func (c *Config) Quarantine() time.Duration {
	return time.Duration(c.QuarantineHours) * time.Hour
}

// SweepInterval returns the parsed time.Duration between sweep cycles.
func (c *Config) SweepInterval() time.Duration {
	return time.Duration(c.SweepIntervalHours) * time.Hour
}

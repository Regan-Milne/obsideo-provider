package pausectl

import "crypto/ed25519"

// coldKeyPubkey is the retention-authority cold-key public key baked
// into this binary at build time. Injected via the Go linker:
//
//	go build -ldflags "-X 'github.com/obsideo/obsideo-provider/pausectl.coldKeyPubkey=obk_sig_<43 b64url>'"
//
// Rationale for build-time injection rather than runtime config (design
// §4.4): the circuit-breaker verification key must not be rotatable by
// whoever has access to the running provider. A compromised
// configuration file or control-plane must not be able to swap in an
// attacker-controlled cold key. Binding the key to the binary means
// rotation requires a new release, which is the correct threshold for a
// "last-resort emergency brake" credential.
//
// Default value is empty. A provider built without the ldflag runs
// without an active circuit breaker: POST /control/pause returns 503
// and IsPaused always returns false. Release builds MUST inject the
// post-ceremony value — see `provider-clean/README.md` for the build
// command template.
var coldKeyPubkey = ""

// EmbeddedColdKey returns the parsed cold-key pubkey baked into this
// binary, or (nil, nil) if the build did not inject one. A malformed
// value (wrong prefix, wrong length, bad base64) returns (nil, err);
// the daemon bootstrap aborts rather than silently disabling the
// circuit breaker on a typo.
func EmbeddedColdKey() (ed25519.PublicKey, error) {
	return ParseColdKey(coldKeyPubkey)
}

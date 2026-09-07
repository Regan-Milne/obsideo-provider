package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/obsideo/obsideo-provider/identity"
)

// InitOptions is everything `obsideo-provider init` needs. Only Address is
// required; the rest default to the same values config.example.yaml ships.
type InitOptions struct {
	Address     string // public HTTPS URL of this node, e.g. https://storage.example.com
	Coordinator string // coordinator base URL
	ConfigPath  string // where to write config.yaml
	DataPath    string // data.path
	Port        int    // server.port (what your TLS proxy forwards to)
	Capacity    string // e.g. "10TB", "8 TiB", or bytes
	NobleWallet string // optional payout address
	SkipProbe   bool   // do not self-probe {Address}/health before registering
	NoRegister  bool   // write key + config only
	Force       bool   // overwrite an existing config.yaml
	Out         io.Writer
	Version     string
}

// Init is the five-minute path. It replaces the manual sequence in
// OPERATOR_SETUP.md (fetch key, hand-edit yaml, curl register, paste the id
// back into the yaml) with one command that:
//
//  1. fetches the coordinator's Ed25519 public key from /public-key and
//     refuses anything that is not a raw 32-byte PEM body;
//  2. generates (or loads) this node's signing identity in data.path;
//  3. writes config.yaml;
//  4. serves a temporary /health on the configured port and probes the
//     public address through it, so a wrong DNS record, missing TLS or a
//     proxy pointed at the wrong port is reported here, not as a bare 502
//     from the coordinator;
//  5. registers the node and writes the returned provider id into
//     config.yaml (the heartbeat URL is built from that id, so a label
//     there means the node never comes alive);
//  6. prints what happens next.
//
// Re-running is safe: the identity is stable, and the coordinator matches a
// registration by (public_key, address), so a repeat returns the same id.
func Init(o InitOptions) error {
	w := o.Out
	if w == nil {
		w = os.Stdout
	}
	if o.Coordinator == "" {
		o.Coordinator = "https://coordinator.obsideo.io"
	}
	o.Coordinator = strings.TrimRight(o.Coordinator, "/")
	if o.ConfigPath == "" {
		o.ConfigPath = "config.yaml"
	}
	if o.DataPath == "" {
		o.DataPath = "./data"
	}
	if o.Port == 0 {
		o.Port = 3334
	}
	if o.Address == "" {
		return errors.New("--address is required: the public https:// URL the coordinator will reach this node at")
	}
	addr, err := url.Parse(o.Address)
	if err != nil || addr.Host == "" || (addr.Scheme != "https" && addr.Scheme != "http") {
		return fmt.Errorf("--address %q is not a URL like https://storage.example.com", o.Address)
	}
	if addr.Scheme != "https" && !isLoopback(addr.Hostname()) {
		return errors.New("--address must be https:// (TLS at the node or at a reverse proxy in front of it); plain http is only accepted for 127.0.0.1 / localhost")
	}
	o.Address = strings.TrimRight(o.Address, "/")
	capBytes, err := parseCapacity(o.Capacity)
	if err != nil {
		return err
	}
	if _, err := os.Stat(o.ConfigPath); err == nil && !o.Force {
		return fmt.Errorf("%s already exists; re-run with --force to overwrite it (the signing identity in %s is kept either way)", o.ConfigPath, o.DataPath)
	}

	ua := "obsideo-provider-init/" + o.Version
	client := &http.Client{Timeout: 20 * time.Second}

	// 1. coordinator public key
	fmt.Fprintf(w, "[1/5] coordinator public key  %s/public-key\n", o.Coordinator)
	pemBytes, keyHex, err := fetchCoordinatorKey(client, o.Coordinator, ua)
	if err != nil {
		return fmt.Errorf("fetch coordinator public key: %w", err)
	}
	pubPath := filepath.Join(filepath.Dir(o.ConfigPath), "coordinator_pub.pem")
	if err := os.WriteFile(pubPath, pemBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}
	fmt.Fprintf(w, "      wrote %s  (ed25519 %s…, 32 bytes)\n", pubPath, keyHex[:16])

	// 2. this node's signing identity
	if err := os.MkdirAll(o.DataPath, 0o755); err != nil {
		return fmt.Errorf("create data path %s: %w", o.DataPath, err)
	}
	ident, err := identity.LoadOrCreate(o.DataPath)
	if err != nil {
		return fmt.Errorf("signing identity: %w", err)
	}
	fmt.Fprintf(w, "[2/5] node signing identity   %s  key_id %s  (private key stays in %s, mode 600)\n",
		ident.PublicKeyHex()[:16]+"…", ident.KeyID(), o.DataPath)

	// 3. config.yaml (provider_id filled after registration)
	if err := writeConfig(o, pubPath, "", capBytes); err != nil {
		return err
	}
	fmt.Fprintf(w, "[3/5] wrote %s  (port %d, data %s, capacity %s)\n", o.ConfigPath, o.Port, o.DataPath, humanBytes(capBytes))

	if o.NoRegister {
		fmt.Fprintln(w, "\n--no-register: done. Register later with `obsideo-provider init --address ... --force`, or by hand per OPERATOR_SETUP.md.")
		return nil
	}

	// 4. temporary /health + self-probe through the public address
	stop, err := serveTempHealth(o.Port)
	if err != nil {
		return fmt.Errorf("cannot listen on :%d for the reachability check (is the provider already running? stop it, or pass --skip-probe and register with it running): %w", o.Port, err)
	}
	defer stop()
	if o.SkipProbe {
		fmt.Fprintln(w, "[4/5] reachability check skipped (--skip-probe); the coordinator still checks on register")
	} else {
		fmt.Fprintf(w, "[4/5] reachability check      GET %s/health via the public address\n", o.Address)
		if err := probe(client, o.Address+"/health", ua); err != nil {
			return fmt.Errorf("this node is not reachable at %s from here: %w\n      fix: DNS for %s must point at this host, TLS must terminate on 443, and the proxy must forward to 127.0.0.1:%d.\n      Then re-run init with --force. (The coordinator runs the same check on register and would return 502.)",
				o.Address, err, addr.Hostname(), o.Port)
		}
		if addr.Scheme == "https" {
			fmt.Fprintln(w, "      ok: reachable, TLS valid, proxied to this process")
		} else {
			fmt.Fprintln(w, "      ok: reachable, proxied to this process (plain http: local test only)")
		}
	}

	// 5. register
	fmt.Fprintf(w, "[5/5] register                POST %s/internal/providers/register\n", o.Coordinator)
	reg, err := register(client, o.Coordinator, ua, map[string]any{
		"address":              o.Address,
		"connectivity":         "direct",
		"public_key":           ident.PublicKeyHex(),
		"capacity_bytes":       capBytes,
		"noble_wallet_address": o.NobleWallet,
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if err := writeConfig(o, pubPath, reg.ID, capBytes); err != nil {
		return err
	}
	fmt.Fprintf(w, "      provider id  %s\n      status       %s\n      provider_id written to %s\n", reg.ID, reg.Status, o.ConfigPath)

	fmt.Fprintf(w, `
WHAT HAPPENS NEXT
  1. Your registration is pending. Send the provider id above to Obsideo
     (regan@obsideo.io or the Telegram group). Approval issues your provider
     API key, which comes back to you out of band; it is never emailed
     automatically.
  2. Put the key in %s under coordinator.provider_api_key, then run:
        ./obsideo-provider start --config %s
     The node heartbeats every 30 s. After 10 consecutive heartbeats
     (about five minutes) it becomes eligible to receive objects.
  3. Objects arrive as customers store data; each one is verified by a
     merkle proof challenge on a continuous cycle of roughly four hours.
     You earn for every proof you pass, settled in USDC to
     noble_wallet_address (set it in the config if you left it blank).
  Status page for the network: https://obsideo.io/network/
`, o.ConfigPath, o.ConfigPath)
	if reg.Status == "active" {
		fmt.Fprintln(w, "  (this node was already approved; if you have your API key, just start it.)")
	}
	return nil
}

type registerResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func register(c *http.Client, coord, ua string, body map[string]any) (*registerResp, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, coord+"/internal/providers/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		if resp.StatusCode == http.StatusBadGateway {
			// The coordinator answers 502 when ITS liveness probe of {address}/health
			// fails; Cloudflare in front of it replaces that JSON with a bare
			// "error code: 502", so say what it means here.
			return nil, fmt.Errorf("coordinator answered HTTP 502: it could not reach %s/health from the internet (DNS, TLS certificate, firewall or proxy target); fix and re-run with --force", body["address"])
		}
		return nil, fmt.Errorf("coordinator answered HTTP %d: %s", resp.StatusCode, e.Error)
	}
	var r registerResp
	if err := json.Unmarshal(raw, &r); err != nil || r.ID == "" {
		return nil, fmt.Errorf("unexpected register response: %s", strings.TrimSpace(string(raw)))
	}
	return &r, nil
}

func fetchCoordinatorKey(c *http.Client, coord, ua string) ([]byte, string, error) {
	req, _ := http.NewRequest(http.MethodGet, coord+"/public-key", nil)
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, "", errors.New("response is not a PEM PUBLIC KEY block")
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("key body is %d bytes, want %d (raw ed25519, not SPKI)", len(block.Bytes), ed25519.PublicKeySize)
	}
	return pem.EncodeToMemory(block), hex.EncodeToString(block.Bytes), nil
}

func probe(c *http.Client, u, ua string) error {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s (something else answered, or the proxy is not forwarding to this process)", resp.StatusCode, u)
	}
	if !bytes.Contains(body, []byte(`"init":true`)) {
		return fmt.Errorf("%s answered 200 but it was not this process (another provider instance, or a different service on that name)", u)
	}
	return nil
}

// serveTempHealth answers /health on the configured port for the duration
// of init so the self-probe and the coordinator's liveness check both see
// a live node before the real process is started.
func serveTempHealth(port int) (func(), error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","init":true}`))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

func writeConfig(o InitOptions, pubPath, providerID string, capBytes int64) error {
	idComment := "filled in by `obsideo-provider init` after registration; the heartbeat URL is built from it"
	wallet := o.NobleWallet
	cfg := fmt.Sprintf(`# obsideo-provider configuration, written by `+"`obsideo-provider init`"+` %s on %s.
# Everything here except coordinator.provider_api_key is already correct.

provider_id: %q   # %s

server:
  host: "0.0.0.0"              # bind address; your TLS proxy on 443 forwards to this port
  port: %d
  read_timeout: 30
  write_timeout: 300

data:
  path: %q   # objects/, index/ and provider_identity.key live here

tokens:
  public_key_path: %q   # the coordinator's ed25519 public key, fetched from %s/public-key

coordinator:
  url: %q
  provider_api_key: ""         # issued when Obsideo approves the registration; paste it here and start the node

coverage:
  enabled: true                # daily "which of my objects are still paid for?" refresh; keep true for a live node

# capacity you offered at registration: %d bytes (%s)
noble_wallet_address: %q   # USDC payout address (noble1...); may be left blank and set later
`, o.Version, time.Now().UTC().Format("2006-01-02T15:04Z"), providerID, idComment, o.Port, o.DataPath, pubPath, o.Coordinator, o.Coordinator, capBytes, humanBytes(capBytes), wallet)
	return os.WriteFile(o.ConfigPath, []byte(cfg), 0o600)
}

func parseCapacity(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, errors.New("--capacity is required, e.g. --capacity 10TB (decimal) or 8TiB (binary) or a number of bytes")
	}
	units := []struct {
		suffix string
		mult   float64
	}{
		{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20},
		{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), 64)
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("--capacity %q: not a positive number", s)
			}
			return int64(n * u.mult), nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("--capacity %q: use bytes or a unit suffix (GB, TB, GiB, TiB)", s)
	}
	return n, nil
}

func humanBytes(b int64) string {
	f := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB", "PB"} {
		if f < 1000 || u == "PB" {
			return strconv.FormatFloat(f, 'f', 1, 64) + " " + u
		}
		f /= 1000
	}
	return ""
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

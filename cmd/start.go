package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/obsideo/obsideo-provider/api"
	"github.com/obsideo/obsideo-provider/config"
	"github.com/obsideo/obsideo-provider/coverage"
	"github.com/obsideo/obsideo-provider/dirfetch"
	"github.com/obsideo/obsideo-provider/gc"
	"github.com/obsideo/obsideo-provider/identity"
	"github.com/obsideo/obsideo-provider/pausectl"
	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

// Start loads config, initialises storage, and runs the HTTP server.
// `version` is the provider binary's version string (e.g. "provider-v1-1");
// it's threaded into the heartbeat payload so the coordinator can surface
// fleet-wide version state via /internal/providers.
func Start(cfgPath, version string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log.Printf("config loaded from %s: provider_id=%q coordinator.url=%q data.path=%q",
		cfgPath, cfg.ProviderID, cfg.Coordinator.URL, cfg.Data.Path)

	st, err := store.New(cfg.Data.Path)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	v, err := tokens.NewVerifier(cfg.Tokens.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("load coordinator public key: %w", err)
	}

	// Retention-authority Phase 1 circuit breaker (design §4.4 / §6.7).
	// Cold-key pubkey is pinned at binary build time via ldflags —
	// see pausectl/embedded.go. A build without the ldflag runs with
	// no active circuit breaker: POST /control/pause returns 503 and
	// IsPaused always returns false. A malformed baked-in value is a
	// hard bootstrap error rather than a silent disable — a typo in a
	// release build must fail loudly, not fall back to "no brake."
	coldKey, err := pausectl.EmbeddedColdKey()
	if err != nil {
		return fmt.Errorf("embedded circuit-breaker cold key is malformed: %w", err)
	}
	pauseState, err := pausectl.Load(cfg.Data.Path, coldKey)
	if err != nil {
		return fmt.Errorf("load pause state: %w", err)
	}
	if coldKey == nil {
		log.Printf("circuit breaker: no cold key baked into this binary; POST /control/pause will 503")
	} else if cur := pauseState.Current(time.Now().UTC()); cur != nil {
		log.Printf("circuit breaker: loaded active pause seq=%d expires_at=%s",
			cur.Signal.SequenceNumber, cur.Signal.ExpiresAt)
	}

	// Provider signing identity (signed possession proofs). Generated on
	// first boot, persisted in the data dir, never silently regenerated —
	// a malformed key file is a hard bootstrap error because silently
	// minting a new key would invalidate every proof this provider ever
	// signed. See identity package doc + vault note_signed_proofs_build_plan.
	ident, err := identity.LoadOrCreate(cfg.Data.Path)
	if err != nil {
		return fmt.Errorf("load provider signing identity: %w", err)
	}
	log.Printf("signing identity: public_key=%s key_id=%s", ident.PublicKeyHex(), ident.KeyID())

	srv := api.New(st, v, pauseState, cfg.ProviderID, cfg.AcceptsUncontractedData())
	srv.SetProofSigner(ident)

	// Heartbeat loop: keep coord's LastHeartbeat fresh so placement
	// filter doesn't reject us as stale. Only starts if both
	// provider_id and coordinator.url are configured. Runs for the
	// process lifetime; errors are logged and retried each interval.
	// Per-tick payload includes ground-truth used_bytes/disk_free
	// from the store, plus the operator's noble wallet address from
	// config (sent only when non-empty so a fresh-installed operator
	// doesn't blank coord's existing record).
	if cfg.ProviderID != "" && cfg.Coordinator.URL != "" {
		go runHeartbeatLoop(context.Background(), cfg.Coordinator.URL, cfg.ProviderID, st, cfg.NobleWalletAddress, version, ident.PublicKeyHex())
	} else {
		log.Printf("heartbeat: provider_id or coordinator.url empty; loop disabled (provider will go stale)")
	}

	// Retention-authority Phase 1 coverage refresh. Gated behind
	// cfg.Coverage.Enabled so pre-Phase-1 operators don't start making
	// outbound calls until they've confirmed coord compatibility.
	if cfg.Coverage.Enabled {
		if cfg.Coordinator.URL == "" || cfg.Coordinator.ProviderAPIKey == "" {
			log.Printf("coverage refresh requested but coordinator.url or provider_api_key is empty; refresh disabled")
		} else {
			httpClient := &http.Client{Timeout: time.Duration(cfg.Coverage.RequestTimeoutS) * time.Second}
			client := coverage.NewClient(cfg.Coordinator.URL, cfg.Coordinator.ProviderAPIKey, httpClient)
			refresher := &coverage.Refresher{
				Store:     st,
				Client:    client,
				Interval:  time.Duration(cfg.Coverage.RefreshIntervalS) * time.Second,
				BatchSize: cfg.Coverage.BatchSize,
			}
			// Refresher runs until the process exits; context is scoped
			// to the process lifetime. Shutdown is OS-signal-driven for
			// now (not plumbed here — existing provider-clean runs until
			// killed).
			go refresher.Start(context.Background())
		}
	}

	// Provider-side garbage collection per docs/GC_DESIGN.md. Default
	// off; opt-in via gc.enabled. Reuses the existing coverage cache
	// (store.Store) for candidate discovery and the existing
	// coverage.Client for per-merkle live rechecks. Recheck-before-delete
	// is unconditional in production — the rechecker is wired from the
	// real coverage.Client here; tests inject a fake through SweeperOpts.
	if cfg.GC.Enabled {
		switch {
		case cfg.Coordinator.URL == "" || cfg.Coordinator.ProviderAPIKey == "":
			log.Printf("gc: enabled in config but coordinator.url or provider_api_key is empty; sweeper disabled")
		default:
			gcQuarantine, err := gc.NewQuarantine(cfg.Data.Path)
			if err != nil {
				return fmt.Errorf("init gc quarantine: %w", err)
			}
			gcHTTPClient := &http.Client{
				Timeout: time.Duration(cfg.Coverage.RequestTimeoutS) * time.Second,
			}
			gcRechecker := gc.CoverageRecheckerFromClient(
				gc.DefaultClient(cfg.Coordinator.URL, cfg.Coordinator.ProviderAPIKey, gcHTTPClient),
			)
			sweeper, err := gc.NewSweeper(gc.SweeperOpts{
				Config:     cfg.GC,
				Coverage:   st,
				Quarantine: gcQuarantine,
				Rechecker:  gcRechecker,
				Storage:    st,
			})
			if err != nil {
				return fmt.Errorf("init gc sweeper: %w", err)
			}
			// Lifetime mirrors the heartbeat and refresher loops: ctx
			// scoped to process lifetime; shutdown is signal-driven.
			go sweeper.Start(context.Background())
		}
	}

	// Phase 1 multi-authority directory-fetch loop. Periodically pulls
	// the central-Coord-signed directory and adds any newly-registered
	// authorized signers (DC pubkeys) to the Verifier. Skipped when
	// coordinator URL or provider API key is empty (local dev / not
	// yet onboarded). Failures log + retry; never replaces in-memory
	// trust list with unverified data. See [[dc_transition_plan]]
	// §"Architectural decisions locked" decision 4.
	if cfg.Coordinator.URL != "" && cfg.Coordinator.ProviderAPIKey != "" {
		seedPub := v.SeedKey()
		if seedPub == nil {
			log.Printf("dirfetch: verifier has no seed key; loop disabled (this should not happen if NewVerifier succeeded)")
		} else {
			refresher, err := dirfetch.New(dirfetch.Options{
				CoordURL:    cfg.Coordinator.URL,
				APIKey:      cfg.Coordinator.ProviderAPIKey,
				CoordPubKey: seedPub,
				Verifier:    v,
				Logger:      log.Default(),
			})
			if err != nil {
				log.Printf("dirfetch: init failed: %v (loop disabled)", err)
			} else {
				go refresher.Start(context.Background())
			}
		}
	} else {
		log.Printf("dirfetch: coordinator.url or provider_api_key empty; loop disabled (legacy single-coord trust only)")
	}

	// Staging-cruft sweeper: prune chunked-upload staging dirs older
	// than maxAge once per hour. Closes the orphan-staging loop that
	// was the most likely cause of Yala 2026-05-02 hitting "no space
	// left on device" with declared 8 GB of capacity but only 3 GB
	// of tracked stored data — failed chunked uploads leave ~95 MB
	// per attempt in staging, untracked. 1h matches the chunked-
	// upload session timeout (anything older is genuinely orphaned).
	// Independent of cfg.GC.Enabled because this is local hygiene,
	// not retention-authority policy.
	go runStagingSweeper(context.Background(), st)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: srv.Handler(),
		// Streaming ingest (and large downloads) move multi-GB objects over a
		// single long-lived request/response. The previous absolute
		// ReadTimeout (cfg default 30s) and WriteTimeout (300s) capped
		// transfer time BY SIZE: a throttled 200 MiB single-shot upload died
		// at exactly 30s in local e2e (gateway -> provider uploads a large
		// object as one long PUT, so this is a real ceiling). Bound only the
		// cheap DoS vectors — header slowloris (ReadHeaderTimeout) and idle
		// keep-alives (IdleTimeout) — and leave the body read / response write
		// uncapped. Mirrors the gateway's absolute->idle timeout fix
		// (s3-gateway 4fad48e). NOTE: cfg.Server.WriteTimeout is intentionally
		// no longer applied (it would re-cap large transfers); read_timeout is
		// reused as the header-phase bound. Idle-based per-read body deadlines
		// are the recommended hardening follow-up (see note_provider_streaming).
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadTimeout) * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("obsideo-provider listening on %s", addr)
	return httpSrv.ListenAndServe()
}

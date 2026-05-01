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
	"github.com/obsideo/obsideo-provider/gc"
	"github.com/obsideo/obsideo-provider/pausectl"
	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

// Start loads config, initialises storage, and runs the HTTP server.
func Start(cfgPath string) error {
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

	srv := api.New(st, v, pauseState, cfg.ProviderID, cfg.AcceptsUncontractedData())

	// Heartbeat loop: keep coord's LastHeartbeat fresh so placement
	// filter doesn't reject us as stale. Only starts if both
	// provider_id and coordinator.url are configured. Runs for the
	// process lifetime; errors are logged and retried each interval.
	if cfg.ProviderID != "" && cfg.Coordinator.URL != "" {
		go runHeartbeatLoop(context.Background(), cfg.Coordinator.URL, cfg.ProviderID)
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

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv.Handler(),
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	log.Printf("obsideo-provider listening on %s", addr)
	return httpSrv.ListenAndServe()
}

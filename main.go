package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/obsideo/obsideo-provider/cmd"
)

// Version is the provider binary version, reported on every heartbeat
// so the coordinator can surface fleet-wide version state via
// /internal/providers. Operators see which providers need to upgrade at
// a glance; a "please upgrade" announcement becomes verifiable from
// coord-side after the fact.
//
// Versioning: provider-v{major}-{minor}. Major bumps on
// protocol-breaking provider changes; minor bumps per release. Build
// pipelines may override via ldflags
// (`-ldflags "-X main.Version=provider-v1-2"`); the source default is
// the most recent published release.
var Version = "provider-v1-1"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: obsideo-provider init --address https://... --capacity 10TB [flags] | start [--config <path>] | version")
	}

	switch os.Args[1] {
	case "init":
		// One-shot onboarding: fetch the coordinator key, generate the node
		// identity, write config.yaml, prove the public address reaches this
		// process, register, and write the returned provider id back into
		// the config. See cmd/init.go.
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		var o cmd.InitOptions
		fs.StringVar(&o.Address, "address", "", "public https:// URL of this node (required), e.g. https://storage.example.com")
		fs.StringVar(&o.Capacity, "capacity", "", "storage offered, e.g. 10TB, 8TiB, or bytes (required)")
		fs.StringVar(&o.DataPath, "data", "./data", "data directory (objects, index, signing identity)")
		fs.StringVar(&o.ConfigPath, "config", "config.yaml", "config file to write")
		fs.StringVar(&o.Coordinator, "coordinator", "https://coordinator.obsideo.io", "coordinator base URL")
		fs.IntVar(&o.Port, "port", 3334, "local port the node listens on (your TLS proxy forwards 443 here)")
		fs.StringVar(&o.NobleWallet, "wallet", "", "noble1... USDC payout address (optional, can be set later)")
		fs.BoolVar(&o.SkipProbe, "skip-probe", false, "skip the self-reachability check before registering")
		fs.BoolVar(&o.NoRegister, "no-register", false, "write the key and config only; do not register")
		fs.BoolVar(&o.Force, "force", false, "overwrite an existing config file")
		_ = fs.Parse(os.Args[2:])
		o.Version = Version
		if err := cmd.Init(o); err != nil {
			fmt.Fprintln(os.Stderr, "init failed:", err)
			os.Exit(1)
		}
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgPath := fs.String("config", "config.yaml", "path to config file")
		_ = fs.Parse(os.Args[2:])
		// Log the version on startup so operators can see at a glance
		// what binary they just ran. Coord receives this same string
		// via heartbeat.
		log.Printf("obsideo-provider %s starting (config=%s)", Version, *cfgPath)
		if err := cmd.Start(*cfgPath, Version); err != nil {
			log.Fatal(err)
		}
	case "version", "-v", "--version":
		// Allow `provider-clean version` as a quick local check that
		// matches what the heartbeat will report.
		fmt.Println(Version)
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

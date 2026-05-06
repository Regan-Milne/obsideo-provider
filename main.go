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
		log.Fatal("usage: provider-clean start [--config <path>] | version")
	}

	switch os.Args[1] {
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

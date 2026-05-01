package main

import (
	"flag"
	"log"
	"os"

	"github.com/obsideo/obsideo-provider/cmd"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: provider-clean start [--config <path>]")
	}

	switch os.Args[1] {
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgPath := fs.String("config", "config.yaml", "path to config file")
		_ = fs.Parse(os.Args[2:])
		if err := cmd.Start(*cfgPath); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

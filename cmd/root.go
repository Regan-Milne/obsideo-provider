package cmd

import (
	"fmt"
	"os"

	"github.com/Regan-Milne/obsideo-provider/config"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "datafarmer",
	Short: "Obsideo Data Farmer - earn AKT by storing data",
	Long: `
  Obsideo Data Farmer -- earn AKT by growing the network.

  Run with no arguments to launch the interactive console.
  Or use subcommands for scripting:

    datafarmer start     start the storage provider server
    datafarmer info      check farm status (non-interactive)
    datafarmer harvest   claim accrued rewards (non-interactive)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		if cfg.CoordinatorURL == "" || cfg.ProviderID == "" {
			fmt.Println("  coordinator_url and provider_id must be set in config.yaml")
			fmt.Println("  for the interactive console. Use 'datafarmer start' to run")
			fmt.Println("  the storage server without coordinator config.")
			return nil
		}
		runREPL(cfg)
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "config file path")
}

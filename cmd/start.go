package cmd

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/dgraph-io/badger/v4"
	"github.com/Regan-Milne/obsideo-provider/api"
	"github.com/Regan-Milne/obsideo-provider/config"
	"github.com/Regan-Milne/obsideo-provider/file_system"
	"github.com/Regan-Milne/obsideo-provider/tokens"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start farming -- run the storage provider server",
	RunE:  runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DB.Path, 0755); err != nil {
		return err
	}

	// Open BadgerDB for merkle tree metadata.
	bOpts := badger.DefaultOptions(cfg.DB.Path + "/fs")
	bOpts.Logger = nil
	db, err := badger.Open(bOpts)
	if err != nil {
		return err
	}
	defer db.Close()

	objDir := filepath.Join(cfg.DB.Path, "objects")
	fs, err := file_system.NewFileSystem(db, objDir)
	if err != nil {
		return err
	}
	defer fs.Close()

	ver, err := tokens.NewVerifier(cfg.Tokens.PublicKeyPath)
	if err != nil {
		return err
	}

	srv := api.New(cfg, fs, ver)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Info().Msg("shutting down")
		sCtx, sCancel := context.WithTimeout(context.Background(), 10*1e9)
		defer sCancel()
		_ = srv.Stop(sCtx)
	}()

	return srv.Start()
}

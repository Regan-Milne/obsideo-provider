package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
	"github.com/Regan-Milne/obsideo-provider/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var purgeFlag bool

var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Check stored objects for integrity and optionally purge orphans",
	Long: `Scan all stored objects and verify that each merkle root in the
index has a corresponding file on disk.

Objects with tree/ entries but no object file are orphaned -- the provider
claims to have them but can't serve the data. These cause challenge failures
and score penalties.

  datafarmer scrub            report only
  datafarmer scrub --purge    delete orphaned entries`,
	RunE: runScrub,
}

func init() {
	scrubCmd.Flags().BoolVar(&purgeFlag, "purge", false, "delete orphaned entries")
	rootCmd.AddCommand(scrubCmd)
}

func runScrub(cmd *cobra.Command, args []string) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DB.Path, 0755); err != nil {
		return err
	}

	bOpts := badger.DefaultOptions(cfg.DB.Path + "/fs")
	bOpts.Logger = nil
	db, err := badger.Open(bOpts)
	if err != nil {
		return err
	}
	defer db.Close()

	objDir := filepath.Join(cfg.DB.Path, "objects")

	// Collect unique merkle roots from tree/ entries.
	uniqueMerkles := make(map[string]bool)
	err = db.View(func(txn *badger.Txn) error {
		prefix := []byte("tree/")
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := string(it.Item().Key())
			rest := key[len("tree/"):]
			for i, c := range rest {
				if c == '/' {
					uniqueMerkles[rest[:i]] = true
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan tree entries: %w", err)
	}

	// Check each merkle for a corresponding object file on disk.
	var healthy []string
	var orphaned []string

	for merkleHex := range uniqueMerkles {
		objPath := filepath.Join(objDir, merkleHex)
		if _, err := os.Stat(objPath); os.IsNotExist(err) {
			orphaned = append(orphaned, merkleHex)
		} else {
			healthy = append(healthy, merkleHex)
		}
	}

	// Report.
	fmt.Printf("\n  Scrub Results\n")
	fmt.Printf("  ─────────────────────────\n")
	fmt.Printf("  Total merkle roots:  %d\n", len(uniqueMerkles))
	fmt.Printf("  Healthy:             %d\n", len(healthy))
	fmt.Printf("  Orphaned:            %d\n", len(orphaned))

	if len(orphaned) > 0 {
		fmt.Printf("\n  Orphaned merkle roots (tree/ exists, object file missing):\n")
		for _, m := range orphaned {
			fmt.Printf("    %s\n", m)
		}
	}

	if len(orphaned) == 0 {
		fmt.Printf("\n  All objects healthy. Nothing to do.\n\n")
		return nil
	}

	if !purgeFlag {
		fmt.Printf("\n  Run with --purge to remove orphaned entries.\n\n")
		return nil
	}

	// Purge orphaned tree/ entries.
	fmt.Printf("\n  Purging %d orphaned entries...\n", len(orphaned))
	purged := 0
	for _, merkleHex := range orphaned {
		prefix := []byte(fmt.Sprintf("tree/%s/", merkleHex))
		var keys [][]byte
		_ = db.View(func(txn *badger.Txn) error {
			it := txn.NewIterator(badger.IteratorOptions{Prefix: prefix})
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				k := make([]byte, len(it.Item().Key()))
				copy(k, it.Item().Key())
				keys = append(keys, k)
			}
			return nil
		})

		if len(keys) == 0 {
			continue
		}

		err := db.Update(func(txn *badger.Txn) error {
			for _, k := range keys {
				if err := txn.Delete(k); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Error().Err(err).Str("merkle", merkleHex).Msg("failed to purge")
			continue
		}
		purged += len(keys)
		fmt.Printf("    purged %s (%d tree entries)\n", merkleHex, len(keys))
	}

	fmt.Printf("\n  Purged %d tree entries across %d merkle roots.\n\n", purged, len(orphaned))
	return nil
}

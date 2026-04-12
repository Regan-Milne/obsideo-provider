package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
)

type scrubResult struct {
	Total    int      `json:"total"`
	Healthy  int      `json:"healthy"`
	Orphaned []string `json:"orphaned"`
	Purged   bool     `json:"purged"`
}

func (s *Server) handleScrub(w http.ResponseWriter, r *http.Request) {
	// Only allow scrub from localhost.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		writeErr(w, http.StatusForbidden, "scrub only available from localhost")
		return
	}

	doPurge := r.Method == http.MethodPost && r.URL.Query().Get("purge") == "true"

	db := s.fs.DB()
	objDir := s.fs.ObjDir()

	// Collect unique merkle roots from tree/ entries.
	uniqueMerkles := make(map[string]bool)
	err := db.View(func(txn *badger.Txn) error {
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
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("scan: %v", err))
		return
	}

	// Check each merkle for an object file on disk.
	var healthy int
	var orphaned []string
	for merkleHex := range uniqueMerkles {
		objPath := filepath.Join(objDir, merkleHex)
		if _, err := os.Stat(objPath); os.IsNotExist(err) {
			orphaned = append(orphaned, merkleHex)
		} else {
			healthy++
		}
	}

	// Purge if requested.
	if doPurge && len(orphaned) > 0 {
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
			_ = db.Update(func(txn *badger.Txn) error {
				for _, k := range keys {
					_ = txn.Delete(k)
				}
				return nil
			})
		}
	}

	result := scrubResult{
		Total:    len(uniqueMerkles),
		Healthy:  healthy,
		Orphaned: orphaned,
		Purged:   doPurge && len(orphaned) > 0,
	}
	if result.Orphaned == nil {
		result.Orphaned = []string{}
	}
	writeJSON(w, http.StatusOK, result)
}

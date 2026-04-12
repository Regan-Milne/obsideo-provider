package file_system

import (
	"os"

	"github.com/dgraph-io/badger/v4"
	"github.com/rs/zerolog/log"
)

type FileSystem struct {
	db     *badger.DB
	objDir string // path to flat file object storage
}

func NewFileSystem(db *badger.DB, objDir string) (*FileSystem, error) {
	if err := os.MkdirAll(objDir, 0755); err != nil {
		return nil, err
	}
	return &FileSystem{db: db, objDir: objDir}, nil
}

// DB returns the underlying BadgerDB instance. Used by admin endpoints
// (scrub) that need direct index access.
func (f *FileSystem) DB() *badger.DB {
	return f.db
}

func (f *FileSystem) Close() {
	if err := f.db.Close(); err != nil {
		log.Error().Err(err).Msg("error closing database")
	}
}

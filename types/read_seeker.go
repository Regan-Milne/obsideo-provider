package types

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// ReadCloserToReadSeekCloser streams rc to a temp file and returns a seekable reader.
// The caller must call Close() to delete the temp file.
func ReadCloserToReadSeekCloser(rc io.ReadCloser) (io.ReadSeekCloser, error) {
	tmpFile, err := os.CreateTemp("", "provider-data-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	_, err = io.Copy(tmpFile, rc)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to copy data to temp file: %w", err)
	}
	rc.Close()
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to seek temp file: %w", err)
	}
	w := &tempFileReadSeekCloser{File: tmpFile}
	runtime.SetFinalizer(w, func(tf *tempFileReadSeekCloser) {
		if tf != nil {
			_ = tf.Close()
		}
	})
	return w, nil
}

type tempFileReadSeekCloser struct {
	*os.File
	closeOnce sync.Once
}

func (t *tempFileReadSeekCloser) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.File.Close()
		os.Remove(t.Name())
	})
	return err
}

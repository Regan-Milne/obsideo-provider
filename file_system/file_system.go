package file_system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/wealdtech/go-merkletree/v2/sha3"

	providerTypes "github.com/Regan-Milne/obsideo-provider/types"
	treeblake3 "github.com/wealdtech/go-merkletree/v2/blake3"
	"github.com/zeebo/blake3"

	"github.com/dgraph-io/badger/v4"
	"github.com/wealdtech/go-merkletree/v2"

	jsoniter "github.com/json-iterator/go"
	"github.com/rs/zerolog/log"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// BuildTree reads buf in chunkSize blocks, hashes each chunk, and builds a merkle tree.
// Returns (root bytes, exported tree JSON, total bytes read, error).
func BuildTree(buf io.Reader, chunkSize int64, proofType int64) ([]byte, []byte, int, error) {
	size := 0
	data := make([][]byte, 0)
	index := 0

	for {
		b := make([]byte, chunkSize)
		read, _ := buf.Read(b)
		if read == 0 {
			break
		}
		b = b[:read]
		size += read

		var h hash.Hash
		switch proofType {
		case providerTypes.ProofTypeBlake3:
			h = blake3.New()
		default:
			h = sha256.New()
		}

		if _, err := fmt.Fprintf(h, "%d%x", index, b); err != nil {
			log.Warn().Msg("failed to write to hash")
			break
		}
		data = append(data, h.Sum(nil))
		index++
	}

	var ht merkletree.HashType
	switch proofType {
	case providerTypes.ProofTypeBlake3:
		ht = treeblake3.New256()
	default:
		ht = sha3.New512()
	}

	tree, err := merkletree.NewTree(
		merkletree.WithData(data),
		merkletree.WithHashType(ht),
		merkletree.WithSalt(false),
	)
	if err != nil {
		return nil, nil, 0, err
	}

	r := tree.Root()
	exportedTree, err := json.Marshal(tree)
	if err != nil {
		return nil, nil, 0, err
	}

	return r, exportedTree, size, nil
}

// WriteFile stores a file as a flat file on disk and saves the merkle tree in BadgerDB.
func (f *FileSystem) WriteFile(reader providerTypes.FileReader, merkle []byte, owner string, start int64, chunkSize int64, proofType int64) (size int, err error) {
	log.Info().Msgf("writing %x to disk", merkle)

	root, exportedTree, s, err := BuildTree(reader, chunkSize, proofType)
	if err != nil {
		return 0, fmt.Errorf("cannot build tree: %w", err)
	}
	size = s

	if hex.EncodeToString(merkle) != hex.EncodeToString(root) {
		return 0, fmt.Errorf("merkle mismatch: expected %x got %x", merkle, root)
	}

	if _, err = reader.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("cannot seek to start: %w", err)
	}

	// Read all bytes and write to flat file.
	fileBytes, err := io.ReadAll(reader)
	if err != nil {
		return 0, fmt.Errorf("read file bytes: %w", err)
	}

	objPath := filepath.Join(f.objDir, hex.EncodeToString(merkle))
	if err := atomicWrite(objPath, fileBytes); err != nil {
		return 0, fmt.Errorf("write object file: %w", err)
	}

	// Store merkle tree metadata in BadgerDB.
	err = f.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(treeKey(merkle, owner, start), exportedTree); err != nil {
			return fmt.Errorf("cannot set tree %x: %w", merkle, err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	fileCount.Inc()
	return size, nil
}

// atomicWrite writes data to path via a temp file + rename to prevent partial writes.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// DeleteFile removes the tree entry for (merkle, owner, start) and physically deletes
// the file on disk if no other tree entries reference the same merkle root.
func (f *FileSystem) DeleteFile(merkle []byte, owner string, start int64) error {
	return f.removeContract(merkle, owner, start)
}

// DeleteAllForMerkle removes every tree entry for merkle (regardless of owner/start)
// and deletes the underlying file on disk.
func (f *FileSystem) DeleteAllForMerkle(merkle []byte) error {
	prefix := []byte(fmt.Sprintf("tree/%x/", merkle))

	var keys [][]byte
	_ = f.db.View(func(txn *badger.Txn) error {
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
		return nil
	}

	_ = f.db.Update(func(txn *badger.Txn) error {
		for _, k := range keys {
			_ = txn.Delete(k)
		}
		return nil
	})
	fileCount.Sub(float64(len(keys)))

	return f.deleteFile(merkle)
}

func (f *FileSystem) removeContract(merkle []byte, owner string, start int64) error {
	err := f.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(treeKey(merkle, owner, start))
	})
	if err != nil {
		log.Warn().Err(err).Msg("removeContract: delete tree key")
	}

	found := false
	_ = f.db.View(func(txn *badger.Txn) error {
		prefix := []byte(fmt.Sprintf("tree/%x/", merkle))
		it := txn.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()
		it.Rewind()
		found = it.Valid()
		return nil
	})

	if !found {
		log.Debug().Hex("merkle", merkle).Msg("zero entries for merkle root, deleting file")
		return f.deleteFile(merkle)
	}
	return nil
}

func (f *FileSystem) deleteFile(merkle []byte) error {
	log.Info().Msgf("removing %x from disk", merkle)
	fileCount.Dec()

	objPath := filepath.Join(f.objDir, hex.EncodeToString(merkle))
	if err := os.Remove(objPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListFiles returns all stored (merkle, owner, start) tuples.
func (f *FileSystem) ListFiles() ([][]byte, []string, []int64, error) {
	var merkles [][]byte
	var owners []string
	var starts []int64

	err := f.db.View(func(txn *badger.Txn) error {
		prefix := []byte("tree/")
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			k := it.Item().Key()
			newValue := k[len(prefix):]
			merkle, owner, start, err := SplitMerkle(newValue)
			if err != nil {
				return err
			}
			merkles = append(merkles, merkle)
			owners = append(owners, owner)
			starts = append(starts, start)
		}
		return nil
	})
	return merkles, owners, starts, err
}

// ProcessFiles calls fn for every stored (merkle, owner, start).
func (f *FileSystem) ProcessFiles(fn func(merkle []byte, owner string, start int64)) error {
	return f.db.View(func(txn *badger.Txn) error {
		prefix := []byte("tree/")
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			k := it.Item().Key()
			newValue := k[len(prefix):]
			merkle, owner, start, err := SplitMerkle(newValue)
			if err != nil {
				return err
			}
			fn(merkle, owner, start)
		}
		return nil
	})
}

// GetFileTreeByChunk returns the merkle tree and the bytes of a specific chunk.
func (f *FileSystem) GetFileTreeByChunk(merkle []byte, owner string, start int64, chunkToLoad int, chunkSize int, proofType int64) (*merkletree.MerkleTree, []byte, error) {
	var tree merkletree.MerkleTree

	err := f.db.View(func(txn *badger.Txn) error {
		t, err := txn.Get(treeKey(merkle, owner, start))
		if err != nil {
			return fmt.Errorf("tree not found: %w", err)
		}
		return t.Value(func(val []byte) error {
			return json.Unmarshal(val, &tree)
		})
	})
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get tree: %w", err)
	}

	// Read the chunk from the flat file.
	rsc, err := f.GetFileData(merkle)
	if err != nil {
		return nil, nil, err
	}
	defer rsc.Close()

	offset := int64(chunkToLoad) * int64(chunkSize)
	if _, err := rsc.(io.Seeker).Seek(offset, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek to chunk %d: %w", chunkToLoad, err)
	}

	chunkOut := make([]byte, chunkSize)
	n, err := io.ReadFull(rsc, chunkOut)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("read chunk %d: %w", chunkToLoad, err)
	}
	chunkOut = chunkOut[:n]

	if len(chunkOut) == 0 {
		return nil, nil, errors.New("chunk is nil")
	}
	return &tree, chunkOut, nil
}

// CheckTree returns true if a tree entry exists for (merkle, owner, start).
func (f *FileSystem) CheckTree(merkle []byte, owner string, start int64) (bool, error) {
	var found bool
	err := f.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(treeKey(merkle, owner, start))
		if err == nil {
			found = true
			return nil
		}
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
	return found, err
}

// GetFileData returns a seekable reader over the full file bytes.
func (f *FileSystem) GetFileData(merkle []byte) (io.ReadSeekCloser, error) {
	objPath := filepath.Join(f.objDir, hex.EncodeToString(merkle))
	file, err := os.Open(objPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("object %x not found", merkle)
		}
		return nil, err
	}
	return file, nil
}

// ObjDir returns the flat file storage directory path.
func (f *FileSystem) ObjDir() string {
	return f.objDir
}

// DefaultChunkSize is the standard chunk size used during upload.
// Must match the SDK's CHUNK_SIZE (1 MiB) for audit challenges to work.
const DefaultChunkSize = 1024 * 1024

// GetChunkByMerkle reads a single chunk by merkle root and 0-based index.
// Returns the raw chunk bytes and the total number of chunks.
func (f *FileSystem) GetChunkByMerkle(merkle []byte, chunkIndex int) ([]byte, int, error) {
	rsc, err := f.GetFileData(merkle)
	if err != nil {
		return nil, 0, fmt.Errorf("get file data: %w", err)
	}
	defer rsc.Close()

	allBytes, err := io.ReadAll(rsc)
	if err != nil {
		return nil, 0, fmt.Errorf("read file data: %w", err)
	}

	totalChunks := (len(allBytes) + DefaultChunkSize - 1) / DefaultChunkSize
	if chunkIndex < 0 || chunkIndex >= totalChunks {
		return nil, 0, fmt.Errorf("chunk index %d out of range [0, %d)", chunkIndex, totalChunks)
	}

	start := chunkIndex * DefaultChunkSize
	end := start + DefaultChunkSize
	if end > len(allBytes) {
		end = len(allBytes)
	}

	return allBytes[start:end], totalChunks, nil
}

// GetAllChunks reads the full file by merkle root and splits it into chunks.
func (f *FileSystem) GetAllChunks(merkle []byte) ([][]byte, error) {
	rsc, err := f.GetFileData(merkle)
	if err != nil {
		return nil, fmt.Errorf("get file data: %w", err)
	}
	defer rsc.Close()

	allBytes, err := io.ReadAll(rsc)
	if err != nil {
		return nil, fmt.Errorf("read file data: %w", err)
	}

	var chunks [][]byte
	for i := 0; i < len(allBytes); i += DefaultChunkSize {
		end := i + DefaultChunkSize
		if end > len(allBytes) {
			end = len(allBytes)
		}
		chunks = append(chunks, allBytes[i:end])
	}

	return chunks, nil
}

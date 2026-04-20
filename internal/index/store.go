package index

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

const (
	// CVEBucket is the name of the bucket storing CVE data
	CVEBucket = "cves"
	// MetaBucket stores per-file metadata so we can detect updates/deletes
	MetaBucket = "filemeta"
)

// FileMeta tracks minimal file information for change detection.
type FileMeta struct {
	ModTime int64  `json:"modTime"`
	Size    int64  `json:"size"`
	DocID   string `json:"docId"`
}

// Store represents a BoltDB-backed storage for CVE data
type Store struct {
	db *bolt.DB
}

// NewStore creates a new BoltDB store at the given path
func NewStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt db: %w", err)
	}

	// Create bucket if it doesn't exist
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(CVEBucket)); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists([]byte(MetaBucket))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	return &Store{db: db}, nil
}

// Put stores a CVE record in the database
func (s *Store) Put(cveID string, data interface{}) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CVEBucket))

		bytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal CVE data: %w", err)
		}

		return b.Put([]byte(cveID), bytes)
	})
}

// Delete removes a CVE record from the database.
func (s *Store) Delete(cveID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CVEBucket))
		return b.Delete([]byte(cveID))
	})
}

// Get retrieves a CVE record from the database
func (s *Store) Get(cveID string) ([]byte, error) {
	var data []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CVEBucket))
		data = b.Get([]byte(cveID))
		if data == nil {
			return fmt.Errorf("CVE %s not found", cveID)
		}
		return nil
	})
	return data, err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// ForEach executes fn for each CVE record in the database
func (s *Store) ForEach(fn func(k []byte, v []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CVEBucket))
		return b.ForEach(fn)
	})
}

// Stats returns statistics about the database
func (s *Store) Stats() (stats bolt.Stats) {
	s.db.View(func(tx *bolt.Tx) error {
		stats = tx.DB().Stats()
		return nil
	})
	return stats
}

// PutMeta stores metadata for a file path.
func (s *Store) PutMeta(path string, meta FileMeta) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(MetaBucket))
		bytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("failed to marshal file meta: %w", err)
		}
		return b.Put([]byte(path), bytes)
	})
}

// GetMeta retrieves metadata for a file path.
func (s *Store) GetMeta(path string) (FileMeta, error) {
	var meta FileMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(MetaBucket))
		data := b.Get([]byte(path))
		if data == nil {
			return fmt.Errorf("metadata for %s not found", path)
		}
		return json.Unmarshal(data, &meta)
	})
	return meta, err
}

// DeleteMeta removes metadata for a file path.
func (s *Store) DeleteMeta(path string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(MetaBucket))
		return b.Delete([]byte(path))
	})
}

// ForEachMeta executes fn for each metadata entry.
func (s *Store) ForEachMeta(fn func(path string, meta FileMeta) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(MetaBucket))
		return b.ForEach(func(k, v []byte) error {
			var meta FileMeta
			if err := json.Unmarshal(v, &meta); err != nil {
				return fmt.Errorf("failed to unmarshal metadata for %s: %w", string(k), err)
			}
			return fn(string(k), meta)
		})
	})
}

package index

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"os"

	"cveapi/internal/files"

	"github.com/blevesearch/bleve/v2"
)

// Index represents a search index for CVE records
type Index struct {
	index bleve.Index
	store *Store
	path  string
}

// heap structures used by ListLatest
type _heapItem struct {
	rec *files.CVERecord
}

type _minHeap []*_heapItem

func (h _minHeap) Len() int { return len(h) }
func (h _minHeap) Less(i, j int) bool {
	return h[i].rec.CveMetadata.DatePublished.Before(h[j].rec.CveMetadata.DatePublished)
}
func (h _minHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *_minHeap) Push(x interface{}) { *h = append(*h, x.(*_heapItem)) }
func (h *_minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// NewIndex creates a new search index at the given path
func NewIndex(indexPath, storePath string) (*Index, error) {
	// Create store
	store, err := NewStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Create or open index
	var index bleve.Index

	// Try to open existing index first
	index, err = bleve.Open(indexPath)
	if err != nil {
		// If index doesn't exist or is corrupt, remove it and create new
		if err == bleve.ErrorIndexPathDoesNotExist || err == bleve.ErrorIndexMetaMissing {
			// Remove any existing corrupt index
			_ = os.RemoveAll(indexPath)

			// Create a new index with a mapping that treats the published date as a date field
			mapping := bleve.NewIndexMapping()

			// Create a document mapping and ensure date fields are treated as datetime fields
			dateMapping := bleve.NewDateTimeFieldMapping()
			dateMapping.Store = true
			dateMapping.IncludeInAll = false

			// store CVE id for quick retrieval from stored fields
			idMapping := bleve.NewTextFieldMapping()
			idMapping.Store = true
			docMapping := bleve.NewDocumentMapping()
			// Bleve flattens JSON field names to lowercase dotted paths (see bleve check)
			docMapping.AddFieldMappingsAt("cveMetadata.datePublished", dateMapping)
			docMapping.AddFieldMappingsAt("cveMetadata.dateUpdated", dateMapping)
			docMapping.AddFieldMappingsAt("cveMetadata.dateReserved", dateMapping)
			docMapping.AddFieldMappingsAt("cveMetadata.cveId", idMapping)

			// Use the document mapping as the default so nested structs are covered
			mapping.DefaultMapping = docMapping

			index, err = bleve.New(indexPath, mapping)
			if err != nil {
				store.Close() // Clean up store if index creation fails
				return nil, fmt.Errorf("failed to create new index: %w", err)
			}
		} else {
			store.Close() // Clean up store if index opening fails
			return nil, fmt.Errorf("failed to open index: %w", err)
		}
	}

	return &Index{
		index: index,
		store: store,
		path:  indexPath,
	}, nil
}

// Index adds a document to the search index
func (idx *Index) Index(id string, doc interface{}) error {
	// Store the full document
	if err := idx.store.Put(id, doc); err != nil {
		return fmt.Errorf("failed to store document: %w", err)
	}

	// Index for search
	if err := idx.index.Index(id, doc); err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}

	return nil
}

// Search performs a search query on the index
func (idx *Index) Search(query string) (*bleve.SearchResult, error) {
	q := bleve.NewQueryStringQuery(query)
	searchRequest := bleve.NewSearchRequest(q)
	return idx.index.Search(searchRequest)
}

// Delete removes a document from both the index and store.
func (idx *Index) Delete(id string) error {
	if err := idx.index.Delete(id); err != nil {
		return fmt.Errorf("failed to delete from index: %w", err)
	}
	if err := idx.store.Delete(id); err != nil {
		return fmt.Errorf("failed to delete from store: %w", err)
	}
	return nil
}

// Get retrieves a document by ID
func (idx *Index) Get(id string) ([]byte, error) {
	return idx.store.Get(id)
}

// Close closes both the index and store
func (idx *Index) Close() error {
	if err := idx.index.Close(); err != nil {
		return fmt.Errorf("failed to close index: %w", err)
	}
	if err := idx.store.Close(); err != nil {
		return fmt.Errorf("failed to close store: %w", err)
	}
	return nil
}

// Count returns the number of documents in the index
func (idx *Index) Count() (uint64, error) {
	return idx.index.DocCount()
}

// Reindex rebuilds the search index from the stored documents
func (idx *Index) Reindex() error {
	// First, delete all documents from the index
	err := idx.index.Close()
	if err != nil {
		return fmt.Errorf("failed to close index: %w", err)
	}

	if err := os.RemoveAll(idx.path); err != nil {
		return fmt.Errorf("failed to remove existing index: %w", err)
	}

	// Recreate the index
	mapping := bleve.NewIndexMapping()
	index, err := bleve.New(idx.path, mapping)
	if err != nil {
		return fmt.Errorf("failed to create new index: %w", err)
	}
	idx.index = index

	// Reindex all documents from store
	return idx.store.ForEach(func(k, v []byte) error {
		var doc interface{}
		if err := json.Unmarshal(v, &doc); err != nil {
			return fmt.Errorf("failed to unmarshal document: %w", err)
		}

		if err := idx.index.Index(string(k), doc); err != nil {
			return fmt.Errorf("failed to index document: %w", err)
		}
		return nil
	})
}

// ListLatest returns up to `limit` CVERecords stored in the underlying Bolt store,
// sorted by DatePublished descending. If limit <= 0 it defaults to 50.
func (idx *Index) ListLatest(limit int) ([]files.CVERecord, error) {
	if limit <= 0 {
		limit = 50
	}

	// Use Bleve to fetch the latest documents sorted by CveMetadata.DatePublished.
	// This avoids scanning the entire Bolt store on every request.
	// If Bleve search fails for any reason, fall back to the store iteration approach.
	q := bleve.NewMatchAllQuery()
	req := bleve.NewSearchRequestOptions(q, limit, 0, false)
	// Sort descending by the nested date field
	req.SortBy([]string{"-cveMetadata.datePublished"})

	res, err := idx.index.Search(req)
	if err == nil {
		out := make([]files.CVERecord, 0, len(res.Hits))
		for _, hit := range res.Hits {
			b, err := idx.store.Get(hit.ID)
			if err != nil {
				// skip missing/broken entries
				continue
			}
			var rec files.CVERecord
			if err := json.Unmarshal(b, &rec); err != nil {
				continue
			}
			out = append(out, rec)
		}
		return out, nil
	}

	// Fallback: iterate store and pick top-N (existing behavior)
	h := &_minHeap{}
	heap.Init(h)

	if err := idx.store.ForEach(func(k, v []byte) error {
		var rec files.CVERecord
		if err := json.Unmarshal(v, &rec); err != nil {
			// skip invalid entries
			return nil
		}

		heap.Push(h, &_heapItem{rec: &rec})
		if h.Len() > limit {
			heap.Pop(h)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate store: %w", err)
	}

	// Extract items from heap into slice (ascending), then reverse to descending
	n := h.Len()
	out := make([]files.CVERecord, 0, n)
	for h.Len() > 0 {
		it := heap.Pop(h).(*_heapItem)
		out = append(out, *it.rec)
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out, nil
}

// SetFileMeta saves metadata for a given file path.
func (idx *Index) SetFileMeta(path string, meta FileMeta) error {
	return idx.store.PutMeta(path, meta)
}

// FileMeta retrieves metadata for a given file path.
func (idx *Index) FileMeta(path string) (FileMeta, error) {
	return idx.store.GetMeta(path)
}

// DeleteFileMeta removes metadata for a given file path.
func (idx *Index) DeleteFileMeta(path string) error {
	return idx.store.DeleteMeta(path)
}

// ForEachFileMeta iterates over file metadata entries.
func (idx *Index) ForEachFileMeta(fn func(path string, meta FileMeta) error) error {
	return idx.store.ForEachMeta(fn)
}

// MappingJSON returns the Bleve index mapping marshaled as JSON.
func (idx *Index) MappingJSON() ([]byte, error) {
	m := idx.index.Mapping()
	return json.MarshalIndent(m, "", "  ")
}

// Fields returns the list of field names present in the underlying Bleve index.
func (idx *Index) Fields() ([]string, error) {
	return idx.index.Fields()
}

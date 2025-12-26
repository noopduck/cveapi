// package files traverse cves and locate the lastest CVE's with score above 7
package files

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Logger is used for warnings and diagnostic messages in this package.
// It defaults to the standard library logger but can be replaced by consumers.
var Logger *log.Logger

func init() {
	Logger = log.Default()
}

// FileHandler is called for every file encountered by TraverseDir.
// path is the full path to the file and d is the DirEntry for the file.
// Return an error to stop walking.
type FileHandler func(path string, d fs.DirEntry) error

// TraverseDir walks a directory and invokes the provided handler for each file.
// If handler is nil it does nothing. Errors returned by the handler stop the walk.
func TraverseDir(root string, handler FileHandler) error {
	if handler == nil {
		return nil
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return handler(path, d)
	})
}

// ReadFile reads and unmarshals a CVE JSON file. Returns an error on failure.
func ReadFile(path string) (CVERecord, error) {
	var rec CVERecord
	content, err := os.ReadFile(path)
	if err != nil {
		return rec, fmt.Errorf("read file %s: %w", path, err)
	}
	if err := json.Unmarshal(content, &rec); err != nil {
		return rec, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return rec, nil
}

// TokenizeFile splits raw content into tokens (words). Simple whitespace split.
func TokenizeFile(content string) []string {
	return strings.Fields(content)
}

// heap item and min-heap used by CollectLatest
type _heapItem struct {
	rec *CVERecord
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

// FindByFilename searches root for files whose filename contains the provided pattern
// and returns the matched CVERecords. It stops on Walk errors but skips files that
// cannot be parsed.
func FindByFilename(root, pattern string) ([]CVERecord, error) {
	var results []CVERecord
	err := TraverseDir(root, func(path string, d fs.DirEntry) error {
		if strings.Contains(d.Name(), pattern) {
			rec, err := ReadFile(path)
			if err != nil {
				// skip unreadable files but continue walking
				Logger.Printf("warning: skipping %s: %v", path, err)
				return nil
			}
			results = append(results, rec)
		}
		return nil
	})
	return results, err
}

// CollectLatest returns up to 'limit' CVERecords sorted by DatePublished descending.
// If limit <= 0 it defaults to 50.
func CollectLatest(root string, limit int) ([]CVERecord, error) {
	if limit <= 0 {
		limit = 50
	}

	// Use package-level min-heap to keep at most `limit` items while streaming files.
	h := &_minHeap{}
	heap.Init(h)

	err := TraverseDir(root, func(path string, d fs.DirEntry) error {
		rec, err := ReadFile(path)
		if err != nil {
			// skip files we can't read
			Logger.Printf("warning: skipping %s: %v", path, err)
			return nil
		}

		heap.Push(h, &_heapItem{rec: &rec})
		if h.Len() > limit {
			heap.Pop(h)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// extract items from heap into slice and sort descending by DatePublished
	n := h.Len()
	out := make([]CVERecord, 0, n)
	for h.Len() > 0 {
		it := heap.Pop(h).(*_heapItem)
		out = append(out, *it.rec)
	}

	// out currently is ascending by DatePublished because we popped from min-heap,
	// so reverse to get descending order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out, nil
}

// TokenizeFileFromPath reads file at path and tokenizes its content as a string.
// It returns tokens and any error encountered while reading the file.
func TokenizeFileFromPath(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return TokenizeFile(string(b)), nil
}

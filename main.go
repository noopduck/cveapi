package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cveapi/internal/files"
	"cveapi/internal/index"
	"cveapi/internal/worker"
)

type Config struct {
	ServerPort  string   `json:"ServerPort"`
	EnableTLS   bool     `json:"EnableTLS"`
	CertFile    string   `json:"CertFile"`
	KeyFile     string   `json:"KeyFile"`
	BasePath    string   `json:"BasePath"`
	IndexPath   string   `json:"IndexPath"`
	StorePath   string   `json:"StorePath"`
	IgnoreFiles []string `json:"IgnoreFiles,omitempty"`
	AsyncIndex  bool     `json:"AsyncIndex,omitempty"`
}

type Server struct {
	config Config
	index  *index.Index
}

func Contains(arr []string, comparator string) bool {
	for _, k := range arr {
		if comparator == k {
			return true
		}
	}

	return false
}

func (s *Server) ListCVEHandler(w http.ResponseWriter, r *http.Request) {
	// Return top 50 latest CVEs. Prefer index-backed listing for better performance
	records, err := s.index.ListLatest(50)
	if err != nil {
		// Fall back to file-based collection if index listing fails
		recordsFile, ferr := files.CollectLatest(s.config.BasePath, 50)
		if ferr != nil {
			http.Error(w, fmt.Sprintf("error collecting CVEs: %v; fallback error: %v", err, ferr), http.StatusInternalServerError)
			return
		}
		records = recordsFile
	}

	out, err := json.Marshal(records)
	if err != nil {
		http.Error(w, fmt.Sprintf("error marshalling: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (s *Server) FindCVEIDHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("search")
	if id == "" {
		http.Error(w, "missing search parameter", http.StatusBadRequest)
		return
	}

	// Search by ID in the index
	result, err := s.index.Search("id:" + id)
	if err != nil {
		http.Error(w, fmt.Sprintf("search error: %v", err), http.StatusInternalServerError)
		return
	}

	if result.Total == 0 {
		// Do not fall back to filesystem traversal; only look up inside the Bolt store.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	// Build full records from index/store for better completeness and consistency
	var records []files.CVERecord
	for _, hit := range result.Hits {
		b, err := s.index.Get(hit.ID)
		if err != nil {
			// if a stored doc can't be read, skip but log a warning
			log.Printf("warning: failed to get document %s from store: %v", hit.ID, err)
			continue
		}
		var rec files.CVERecord
		if err := json.Unmarshal(b, &rec); err != nil {
			log.Printf("warning: failed to unmarshal stored document %s: %v", hit.ID, err)
			continue
		}
		records = append(records, rec)
	}

	out, err := json.Marshal(records)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal error: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (s *Server) FindCVEHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("search")
	if q == "" {
		http.Error(w, "missing search parameter", http.StatusBadRequest)
		return
	}

	// Search in index
	result, err := s.index.Search(q)
	if err != nil {
		http.Error(w, fmt.Sprintf("search error: %v", err), http.StatusInternalServerError)
		return
	}

	// Build full records from index/store for each search hit
	var records []files.CVERecord
	for _, hit := range result.Hits {
		b, err := s.index.Get(hit.ID)
		if err != nil {
			log.Printf("warning: failed to get document %s from store: %v", hit.ID, err)
			continue
		}
		var rec files.CVERecord
		if err := json.Unmarshal(b, &rec); err != nil {
			log.Printf("warning: failed to unmarshal stored document %s: %v", hit.ID, err)
			continue
		}
		records = append(records, rec)
	}

	out, err := json.Marshal(records)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal error: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// IndexMappingsHandler returns the Bleve index mapping as JSON (no external CLI).
func (s *Server) IndexMappingsHandler(w http.ResponseWriter, r *http.Request) {
	b, err := s.index.MappingJSON()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mapping: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// IndexFieldsHandler returns the list of actual field names stored in the Bleve index.
func (s *Server) IndexFieldsHandler(w http.ResponseWriter, r *http.Request) {
	fields, err := s.index.Fields()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get index fields: %v", err), http.StatusInternalServerError)
		return
	}

	out, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal fields: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func readConfigurationFile() Config {
	config, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Error reading configuration file: %v", err)
	}

	var conf Config
	if err := json.Unmarshal(config, &conf); err != nil {
		log.Fatalf("Error parsing configuration file: %v", err)
	}

	// Set default paths if not specified
	if conf.IndexPath == "" {
		conf.IndexPath = "index"
	}
	if conf.StorePath == "" {
		conf.StorePath = "store.db"
	}

	log.Printf("Parsed Configuration: %+v", conf)
	return conf
}

func buildIndex(config *Config) *index.Index {
	if config == nil {
		log.Fatalf("buildIndex received nil config")
	}

	normalizePath := func(p string) string {
		if p == "" {
			return ""
		}
		p = filepath.Clean(p)
		if !filepath.IsAbs(p) {
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
		}
		return p
	}

	config.BasePath = normalizePath(config.BasePath)
	if config.BasePath == "" {
		log.Fatalf("BasePath must be set")
	}
	if _, err := os.Stat(config.BasePath); err != nil {
		log.Fatalf("BasePath %s is invalid: %v", config.BasePath, err)
	}

	indexPath := normalizePath(config.IndexPath)
	if indexPath == "" {
		indexPath = filepath.Join(config.BasePath, ".index")
		log.Printf("IndexPath not provided; defaulting to %s", indexPath)
	}
	if indexPath == config.BasePath {
		indexPath = filepath.Join(config.BasePath, ".index")
		log.Printf("IndexPath %s matches BasePath; using %s for index storage", config.IndexPath, indexPath)
	}
	config.IndexPath = indexPath

	config.StorePath = normalizePath(config.StorePath)
	if config.StorePath == "" {
		config.StorePath = filepath.Join(config.BasePath, "store.db")
		log.Printf("StorePath not provided; defaulting to %s", config.StorePath)
	}

	// Create index
	idx, err := index.NewIndex(config.IndexPath, config.StorePath)
	if err != nil {
		log.Fatalf("Failed to create index: %v", err)
	}

	if config.AsyncIndex {
		go runIndexing(idx, config)
		return idx
	}

	// synchronous (tests)
	runIndexing(idx, config)
	return idx
}

// runIndexing performs the file-walking and worker-pool indexing. It logs
// progress and errors. It may be called synchronously or in a goroutine.
func runIndexing(idx *index.Index, config *Config) {
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel

	pool := worker.NewPool(ctx, runtime.NumCPU(), func(task worker.Task) error {
		return indexFile(idx, task.FilePath)
	})

	pool.Start()

	resultErrors := make(chan []error, 1)
	go func() {
		var errs []error
		for result := range pool.Results() {
			if result.Error != nil {
				errs = append(errs, fmt.Errorf("error processing %s: %v", result.Task.ID, result.Error))
			}
		}
		resultErrors <- errs
	}()

	indexUnderBase := strings.HasPrefix(config.IndexPath, config.BasePath+string(os.PathSeparator))

	// Walk through CVE files and submit indexing tasks.
	walkErr := filepath.Walk(config.BasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if indexUnderBase && path == config.IndexPath {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		pool.Submit(worker.Task{
			ID:       filepath.Base(path),
			FilePath: path,
		})

		return nil
	})
	if walkErr != nil {
		pool.Stop()
		<-resultErrors
		log.Fatalf("Failed to walk data directory: %v", walkErr)
	}

	pool.Stop()
	errors := <-resultErrors
	if len(errors) > 0 {
		log.Printf("Encountered %d errors during indexing:", len(errors))
		for _, err := range errors {
			log.Printf("  %v", err)
		}
	} else {
		if count, err := idx.Count(); err == nil {
			log.Printf("Index build complete. Indexed %d documents.", count)
		} else {
			log.Printf("Index build complete. Failed to fetch document count: %v", err)
		}
	}
}

func indexFile(idx *index.Index, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var cveRecord files.CVERecord
	if err := json.Unmarshal(data, &cveRecord); err != nil {
		return fmt.Errorf("failed to parse JSON from %s: %w", path, err)
	}

	docID := filepath.Base(path)

	if err := idx.Index(docID, cveRecord); err != nil {
		return fmt.Errorf("failed to index %s: %w", path, err)
	}

	meta := index.FileMeta{
		ModTime: info.ModTime().UnixNano(),
		Size:    info.Size(),
		DocID:   docID,
	}
	if err := idx.SetFileMeta(path, meta); err != nil {
		return fmt.Errorf("failed to store metadata for %s: %w", path, err)
	}

	return nil
}

func syncOnce(basePath, indexPath string, idx *index.Index) error {
	// tests expect this signature (no ignoreFiles). Default to no ignores.
	seen := make(map[string]struct{})
	var errs []error
	indexUnderBase := strings.HasPrefix(indexPath, basePath+string(os.PathSeparator))

	walkErr := filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			if indexUnderBase && path == indexPath {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}

		seen[path] = struct{}{}

		info, err := d.Info()
		if err != nil {
			errs = append(errs, fmt.Errorf("stat %s: %w", path, err))
			return nil
		}

		meta, err := idx.FileMeta(path)
		if err == nil && meta.ModTime == info.ModTime().UnixNano() && meta.Size == info.Size() {
			return nil
		}

		if err := indexFile(idx, path); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}

	var stale []struct {
		path string
		meta index.FileMeta
	}

	metaErr := idx.ForEachFileMeta(func(path string, meta index.FileMeta) error {
		if _, ok := seen[path]; ok {
			return nil
		}

		if _, err := os.Stat(path); err == nil {
			// File still exists but we didn't visit it (probably wrong extension); keep metadata.
			return nil
		}

		stale = append(stale, struct {
			path string
			meta index.FileMeta
		}{path: path, meta: meta})
		return nil
	})
	if metaErr != nil {
		errs = append(errs, metaErr)
	}

	for _, st := range stale {
		if err := idx.Delete(st.meta.DocID); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", st.meta.DocID, err))
		}
		if err := idx.DeleteFileMeta(st.path); err != nil {
			errs = append(errs, fmt.Errorf("delete meta %s: %w", st.path, err))
		}
	}

	return errors.Join(errs...)
}

func startSyncLoop(ctx context.Context, basePath, indexPath string, idx *index.Index, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := syncOnce(basePath, indexPath, idx); err != nil {
			log.Printf("incremental sync finished with issues: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func main() {
	config := readConfigurationFile()

	// `AsyncIndex` is now read from `config.json` (defaults to false).
	// Set `asyncIndex: true` in your config to start the server while
	// initial indexing runs in the background.

	// Build search index
	idx := buildIndex(&config)
	defer idx.Close()

	// Start periodic sync to pick up new/changed/deleted CVEs.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startSyncLoop(ctx, config.BasePath, config.IndexPath, idx, 15*time.Minute)

	// Create server
	server := &Server{
		config: config,
		index:  idx,
	}

	// Set up routes
	http.HandleFunc("/list", server.ListCVEHandler)
	http.HandleFunc("/findID", server.FindCVEIDHandler)
	http.HandleFunc("/findText", server.FindCVEHandler)
	http.HandleFunc("/index/mappings", server.IndexMappingsHandler)
	http.HandleFunc("/index/fields", server.IndexFieldsHandler)

	// Serve OpenAPI spec and Swagger UI
	http.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "openapi.json")
	})
	http.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "swagger.html")
	})

	log.Printf("Server port selected: %v", config.ServerPort)

	if config.EnableTLS {
		log.Println("TLS is enabled, starting HTTPS server.")
		certFile := config.CertFile
		keyFile := config.KeyFile

		if err := http.ListenAndServeTLS(":"+config.ServerPort, certFile, keyFile, nil); err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	} else {
		log.Println("TLS is disabled, starting HTTP server.")
		if err := http.ListenAndServe(":"+config.ServerPort, nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}
}

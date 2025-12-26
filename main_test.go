package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cveapi/internal/files"
)

func TestBuildIndexIndexesFiles(t *testing.T) {
	tmp := filepath.Join("testdata", t.Name())
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	base := filepath.Join(tmp, "data")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir base: %v", err)
	}

	src := filepath.Join("examples", "CVE-2024-58266.json")
	dst := filepath.Join(base, "CVE-2024-58266.json")
	bytes, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	if err := os.WriteFile(dst, bytes, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	conf := Config{
		BasePath:  base,
		IndexPath: base, // deliberately collide to ensure buildIndex fixes it
		StorePath: filepath.Join(tmp, "store.db"),
	}

	idx := buildIndex(&conf)
	t.Cleanup(func() { idx.Close() })

	if conf.IndexPath == conf.BasePath {
		t.Fatalf("expected buildIndex to decouple index path from base path")
	}

	if _, err := os.Stat(filepath.Join(conf.BasePath, "CVE-2024-58266.json")); err != nil {
		t.Fatalf("sample file missing after indexing: %v", err)
	}

	count, err := idx.Count()
	if err != nil {
		t.Fatalf("count err: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 doc indexed, got %d", count)
	}

	res, err := idx.Search("CVE-2024-58266")
	if err != nil {
		t.Fatalf("search err: %v", err)
	}
	if res.Total == 0 {
		t.Fatalf("expected search result, got 0")
	}
}

func writeSampleCVE(t *testing.T, path, id, title string, published time.Time) {
	t.Helper()
	rec := files.CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		CveMetadata: files.CVEMetadata{
			CveID:         id,
			DatePublished: files.LocalTime{Time: published},
			DateUpdated:   files.LocalTime{Time: published},
		},
		Containers: files.Containers{
			CNA: files.CNA{
				Title: title,
				Descriptions: []files.LocalizedDescription{
					{Lang: "en", Value: title},
				},
			},
		},
	}

	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal cve: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write cve: %v", err)
	}
}

func TestSyncOnceAddsUpdatesAndDeletes(t *testing.T) {
	tmp := filepath.Join("testdata", t.Name())
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	base := filepath.Join(tmp, "data")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir base: %v", err)
	}

	conf := Config{
		BasePath:  base,
		IndexPath: filepath.Join(tmp, "index"),
		StorePath: filepath.Join(tmp, "store.db"),
	}

	idx := buildIndex(&conf)
	t.Cleanup(func() { idx.Close() })

	// No documents initially
	if count, err := idx.Count(); err != nil || count != 0 {
		t.Fatalf("expected 0 docs, got %d (err=%v)", count, err)
	}

	// Add new CVE and sync
	target := filepath.Join(base, "CVE-TEST-1.json")
	writeSampleCVE(t, target, "CVE-TEST-1", "first-title", time.Now())
	if err := syncOnce(conf.BasePath, conf.IndexPath, idx); err != nil {
		t.Fatalf("syncOnce add: %v", err)
	}

	res, err := idx.Search("first-title")
	if err != nil {
		t.Fatalf("search err: %v", err)
	}
	if res.Total == 0 {
		t.Fatalf("expected search hit after add")
	}

	// Update file contents and sync; ensure new term is searchable
	time.Sleep(10 * time.Millisecond) // ensure modtime changes
	writeSampleCVE(t, target, "CVE-TEST-1", "second-title", time.Now())
	if err := syncOnce(conf.BasePath, conf.IndexPath, idx); err != nil {
		t.Fatalf("syncOnce update: %v", err)
	}

	res, err = idx.Search("second-title")
	if err != nil {
		t.Fatalf("search err: %v", err)
	}
	if res.Total == 0 {
		t.Fatalf("expected search hit after update")
	}

	// Delete file and sync; index/store should drop the document
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := syncOnce(conf.BasePath, conf.IndexPath, idx); err != nil {
		t.Fatalf("syncOnce delete: %v", err)
	}

	count, err := idx.Count()
	if err != nil {
		t.Fatalf("count err: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 docs after delete, got %d", count)
	}
}

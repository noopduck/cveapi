package files

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempCVE(t *testing.T, dir, name string, pub time.Time) {
	rec := CVERecord{
		DataType:    "test",
		DataVersion: "1",
		CveMetadata: CVEMetadata{CveID: name, DatePublished: LocalTime{pub}},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestCollectLatest(t *testing.T) {
	dir := t.TempDir()
	// create 5 files with different dates
	now := time.Now()
	for i := 0; i < 5; i++ {
		name := "CVE-TEST-" + string(rune('A'+i))
		writeTempCVE(t, dir, name, now.Add(time.Duration(i)*-time.Hour))
	}

	// request top 3
	recs, err := CollectLatest(dir, 3)
	if err != nil {
		t.Fatalf("CollectLatest error: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
	// ensure descending order
	for i := 1; i < len(recs); i++ {
		if !recs[i-1].CveMetadata.DatePublished.After(recs[i].CveMetadata.DatePublished) && !recs[i-1].CveMetadata.DatePublished.Equal(recs[i].CveMetadata.DatePublished) {
			t.Fatalf("records not in descending order: %v before %v", recs[i-1].CveMetadata.DatePublished, recs[i].CveMetadata.DatePublished)
		}
	}
}

func TestFindByFilename(t *testing.T) {
	dir := t.TempDir()
	writeTempCVE(t, dir, "match-me", time.Now())
	writeTempCVE(t, dir, "other", time.Now())

	recs, err := FindByFilename(dir, "match")
	if err != nil {
		t.Fatalf("FindByFilename error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 match, got %d", len(recs))
	}
	if recs[0].CveMetadata.CveID != "match-me" {
		t.Fatalf("unexpected id: %s", recs[0].CveMetadata.CveID)
	}
}

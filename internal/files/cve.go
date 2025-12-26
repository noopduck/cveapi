package files

import (
	"fmt"
	"strings"
	"time"
)

type CVERecord struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CveMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

type CVEMetadata struct {
	CveID             string    `json:"cveId"`
	AssignerOrgID     string    `json:"assignerOrgId"`
	State             string    `json:"state"`
	AssignerShortName string    `json:"assignerShortName"`
	DateReserved      LocalTime `json:"dateReserved"`
	DatePublished     LocalTime `json:"datePublished"`
	DateUpdated       LocalTime `json:"dateUpdated"`
}

type LocalTime struct {
	time.Time
}

// UnmarshalJSON parses time in either RFC3339 or "2006-01-02T15:04:05" (without timezone)
func (lt *LocalTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		return nil
	}

	// Prøv først RFC3339 (inneholder tidssone)
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		lt.Time = t
		return nil
	}

	// Prøv uten tidssone (tolk som UTC)
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err == nil {
		lt.Time = t.UTC()
		return nil
	}

	return fmt.Errorf("invalid time format: %s", s)
}

// Gi LocalTime noen av time.Time-metodene
func (lt LocalTime) Before(u LocalTime) bool { return lt.Time.Before(u.Time) }
func (lt LocalTime) After(u LocalTime) bool  { return lt.Time.After(u.Time) }
func (lt LocalTime) Equal(u LocalTime) bool  { return lt.Time.Equal(u.Time) }
func (lt LocalTime) IsZero() bool            { return lt.Time.IsZero() }
func (lt LocalTime) String() string          { return lt.Time.Format(time.RFC3339) }

type Containers struct {
	CNA CNA `json:"cna"`
}

type CNA struct {
	ProviderMetadata ProviderMetadata       `json:"providerMetadata"`
	Title            string                 `json:"title"`
	ProblemTypes     []ProblemType          `json:"problemTypes"`
	Affected         []Affected             `json:"affected"`
	Descriptions     []LocalizedDescription `json:"descriptions"`
	Metrics          []Metric               `json:"metrics"`
	Timeline         []TimelineEntry        `json:"timeline"`
	Credits          []Credit               `json:"credits"`
	References       []Reference            `json:"references"`
}

type ProviderMetadata struct {
	OrgID       string    `json:"orgId"`
	ShortName   string    `json:"shortName"`
	DateUpdated LocalTime `json:"dateUpdated"`
}

type ProblemType struct {
	Descriptions []ProblemTypeDescription `json:"descriptions"`
}

type ProblemTypeDescription struct {
	Type        string `json:"type"`
	CWEID       string `json:"cweId"`
	Lang        string `json:"lang"`
	Description string `json:"description"`
}

type Affected struct {
	Vendor   string    `json:"vendor"`
	Product  string    `json:"product"`
	Versions []Version `json:"versions"`
	Modules  []string  `json:"modules"`
}

type Version struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

type LocalizedDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metric struct {
	CVSSV40 *CVSS   `json:"cvssV4_0,omitempty"`
	CVSSV31 *CVSS   `json:"cvssV3_1,omitempty"`
	CVSSV30 *CVSS   `json:"cvssV3_0,omitempty"`
	CVSSV20 *CVSS20 `json:"cvssV2_0,omitempty"`
}

type CVSS struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
}

type CVSS20 struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type TimelineEntry struct {
	Time  LocalTime `json:"time"`
	Lang  string    `json:"lang"`
	Value string    `json:"value"`
}

type Credit struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

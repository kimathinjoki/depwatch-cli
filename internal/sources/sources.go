// Package sources looks up advisories without a watchdep server: OSV for affected versions, CISA
// KEV for exploited now, and EPSS for the probability of exploitation.
//
// Every source sits behind an interface. Tests use the recorded implementation, which answers from
// a committed file and fails on anything not recorded, so no test reaches the network by default.
package sources

import (
	"context"
	"fmt"
	"strings"
)

// Query asks which advisories affect one package at one version. Ecosystem is OSV's name,
// including the release for operating system packages ("Debian:12").
type Query struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// Key identifies a query in a recording and a cache.
func (q Query) Key() string { return q.Ecosystem + "|" + q.Name + "|" + q.Version }

// Vuln is the part of an OSV entry watchdep reads.
type Vuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases,omitempty"`
	Upstream         []string       `json:"upstream,omitempty"`
	Related          []string       `json:"related,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Modified         string         `json:"modified,omitempty"`
	Published        string         `json:"published,omitempty"`
	Withdrawn        string         `json:"withdrawn,omitempty"`
	Severity         []Severity     `json:"severity,omitempty"`
	Affected         []Affected     `json:"affected,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
	References       []Reference    `json:"references,omitempty"`
}

// Severity is a scoring vector.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one package an entry affects.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl,omitempty"`
	} `json:"package"`
	Ranges            []Range        `json:"ranges,omitempty"`
	Versions          []string       `json:"versions,omitempty"`
	Severity          []Severity     `json:"severity,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
}

// Range is a set of version events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one version event in a range.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CVEs returns the entry's CVE ids: its own id, its aliases and its upstream ids.
func (v *Vuln) CVEs() []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range append(append([]string{v.ID}, v.Aliases...), v.Upstream...) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// KEVEntry is one CVE in CISA's Known Exploited Vulnerabilities catalogue.
type KEVEntry struct {
	CVE               string `json:"cveID"`
	DateAdded         string `json:"dateAdded"`
	VulnerabilityName string `json:"vulnerabilityName,omitempty"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse,omitempty"`
}

// EPSSScore is the probability that a CVE is exploited in the next 30 days.
type EPSSScore struct {
	CVE         string  `json:"cve"`
	Probability float64 `json:"epss"`
	Percentile  float64 `json:"percentile"`
	Date        string  `json:"date"`
}

// OSV finds the advisories affecting packages and reads each one.
type OSV interface {
	// Query returns, for each query's Key, the ids of the advisories affecting it. Every query
	// gets an answer (possibly empty) or the call fails.
	Query(ctx context.Context, qs []Query) (map[string][]string, error)
	Vuln(ctx context.Context, id string) (*Vuln, error)
}

// KEV says which CVEs are exploited now.
type KEV interface {
	Lookup(ctx context.Context, cves []string) (map[string]KEVEntry, error)
}

// EPSS gives exploitation probabilities.
type EPSS interface {
	Scores(ctx context.Context, cves []string) (map[string]EPSSScore, error)
}

// Set is the three sources.
type Set struct {
	OSV  OSV
	KEV  KEV
	EPSS EPSS
}

// Names of the sources, as shown to people.
const (
	NameOSV  = "OSV"
	NameKEV  = "CISA KEV"
	NameEPSS = "EPSS"
)

// Error is a source that could not answer. Nothing about that source reads as clean.
type Error struct {
	Source string
	Err    error
}

func (e *Error) Error() string { return fmt.Sprintf("%s did not answer: %v", e.Source, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

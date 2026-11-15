// Package rank gives a finding its level: severe, high, medium or low, with its labels.
//
// Every rule is a case in testdata/ranking_cases.json. The watchdep service is tested against the
// same cases, so the CLI and the service can never rank differently.
package rank

import (
	"fmt"
	"strings"
)

// Levels, loudest first.
const (
	Severe = "severe"
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Labels.
const (
	LabelExploitedNow = "exploited_now"
	LabelMalicious    = "malicious"
	LabelProvisional  = "provisional"
	LabelUnscored     = "unscored"
	LabelDevelopment  = "development_only"
)

// DefaultEPSSThreshold is the workspace default: a 10 percent probability of exploitation.
const DefaultEPSSThreshold = 0.10

// Input is what ranking reads about one finding.
type Input struct {
	// Scope is "production" when any place the finding appears ships to production.
	Scope     string `json:"scope"`
	KEV       bool   `json:"kev"`
	Malicious bool   `json:"malicious"`
	// CVSS is the highest base score among the advisory's sources; nil when none states one.
	CVSS *float64 `json:"cvss"`
	// SourceLabel is the source's own severity word (critical, high, moderate or medium, low), used
	// when there is no CVSS.
	SourceLabel string `json:"source_label"`
	// EPSS is the probability of exploitation; nil when EPSS has no score yet.
	EPSS *float64 `json:"epss"`
	// EPSSThreshold; zero means DefaultEPSSThreshold.
	EPSSThreshold float64 `json:"epss_threshold,omitempty"`
}

// Result is a level, its labels, and the reason in words.
type Result struct {
	Level  string   `json:"level"`
	Labels []string `json:"labels"`
	Reason string   `json:"reason"`
}

// Band is the CVSS or source severity band: critical, high, medium, low, or "" when unknown.
func Band(cvss *float64, label string) string {
	if cvss != nil && *cvss > 0 {
		switch {
		case *cvss >= 9.0:
			return "critical"
		case *cvss >= 7.0:
			return "high"
		case *cvss >= 4.0:
			return "medium"
		default:
			return "low"
		}
	}
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return ""
}

// Rank applies the rules.
func Rank(in Input) Result {
	threshold := in.EPSSThreshold
	if threshold == 0 {
		threshold = DefaultEPSSThreshold
	}
	var labels []string
	var reasons []string
	if in.KEV {
		labels = append(labels, LabelExploitedNow)
	}
	if in.Malicious {
		labels = append(labels, LabelMalicious)
	}

	// Malicious releases are always severe, in any scope: the remedy is to remove the version now.
	if in.Malicious {
		return Result{Level: Severe, Labels: labels, Reason: "a malicious release; remove this version now"}
	}

	band := Band(in.CVSS, in.SourceLabel)
	bandText := band
	if in.CVSS != nil && *in.CVSS > 0 {
		bandText = fmt.Sprintf("%s (CVSS %.1f)", band, *in.CVSS)
	} else if band != "" {
		bandText = band + " (the source's own label)"
	}
	epssHigh := in.EPSS != nil && *in.EPSS >= threshold
	epssText := "no EPSS score yet"
	if in.EPSS != nil {
		epssText = fmt.Sprintf("EPSS %.1f%%", *in.EPSS*100)
	}

	var level string
	switch {
	case in.KEV:
		level = Severe
		reasons = append(reasons, "listed in CISA KEV: exploited now")
	case band == "":
		// No severity of any kind: high, the louder answer, until a source states one.
		level = High
		labels = append(labels, LabelUnscored)
		reasons = append(reasons, "no severity stated by any source")
	case band == "critical" && in.EPSS == nil:
		level = Severe
		labels = append(labels, LabelProvisional)
		reasons = append(reasons, bandText+" with no EPSS score yet; provisional")
	case band == "critical" && epssHigh:
		level = Severe
		reasons = append(reasons, bandText+" with "+epssText)
	case band == "critical":
		level = High
		reasons = append(reasons, bandText+" with "+epssText+", below the threshold")
	case band == "high":
		level = High
		reasons = append(reasons, bandText)
	case band == "medium" && epssHigh:
		level = High
		reasons = append(reasons, bandText+" raised by "+epssText)
	case band == "medium":
		level = Medium
		reasons = append(reasons, bandText)
	case band == "low" && epssHigh:
		level = Medium
		reasons = append(reasons, bandText+" raised by "+epssText)
	default:
		level = Low
		reasons = append(reasons, bandText)
	}

	if in.Scope != "production" {
		labels = append(labels, LabelDevelopment)
		dropped := drop(level)
		if dropped != level {
			reasons = append(reasons, "development only: dropped from "+level+" to "+dropped)
		}
		level = dropped
	}
	if labels == nil {
		labels = []string{}
	}
	return Result{Level: level, Labels: labels, Reason: strings.Join(reasons, "; ")}
}

func drop(level string) string {
	switch level {
	case Severe:
		return High
	case High:
		return Medium
	default:
		return Low
	}
}

// Order gives a level's loudness: severe 4 down to low 1.
func Order(level string) int {
	switch level {
	case Severe:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

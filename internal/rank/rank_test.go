package rank

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type rankingCase struct {
	Name     string `json:"name"`
	Input    Input  `json:"input"`
	Expected struct {
		Level  string   `json:"level"`
		Labels []string `json:"labels"`
	} `json:"expected"`
}

// TestRankingCases runs every case in the shared file; the server runs the same file.
func TestRankingCases(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/ranking_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []rankingCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("only %d ranking cases; a case was dropped", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := Rank(c.Input)
			if got.Level != c.Expected.Level {
				t.Errorf("level %s, want %s (%s)", got.Level, c.Expected.Level, got.Reason)
			}
			if !slices.Equal(got.Labels, c.Expected.Labels) {
				t.Errorf("labels %v, want %v", got.Labels, c.Expected.Labels)
			}
			if got.Reason == "" {
				t.Error("no reason given")
			}
		})
	}
}

func TestBand(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		cvss  *float64
		label string
		want  string
	}{{f(9.0), "", "critical"}, {f(8.9), "", "high"}, {f(7.0), "", "high"}, {f(6.9), "", "medium"}, {f(4.0), "", "medium"}, {f(3.9), "", "low"}, {nil, "Moderate", "medium"}, {nil, "", ""}, {f(0), "high", "high"}} {
		if got := Band(c.cvss, c.label); got != c.want {
			t.Errorf("Band(%v, %q) = %q, want %q", c.cvss, c.label, got, c.want)
		}
	}
}

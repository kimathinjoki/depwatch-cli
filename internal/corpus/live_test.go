//go:build live

package corpus

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kimathinjoki/watchdep-cli/internal/sources"
	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

var update = flag.Bool("update", false, "write fresh recordings and expected results")

// TestCorpusLive re-runs the corpus against the real sources and reports any difference from the
// recordings. With -update it writes new recordings and expected results instead, to be reviewed.
//
//	go test -tags live ./internal/corpus -run TestCorpusLive -v
//	go test -tags live ./internal/corpus -run TestCorpusLive -update
func TestCorpusLive(t *testing.T) {
	for _, name := range Cases {
		t.Run(name, func(t *testing.T) {
			c, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			rec := sources.NewRecorder(sources.Live(version.UserAgent(), 90*time.Second))
			src := rec.Sources()
			if c.DropEPSS {
				src.EPSS = noScores{src.EPSS}
			}
			if len(c.Fail) > 0 {
				// The stalled-source case records the live answers, then fails the named source.
				if _, _, err := Run(name, Case{Args: c.Args}, src); err != nil {
					t.Fatal(err)
				}
				rec.Rec.Fail = c.Fail
				src = rec.Rec.Sources()
				rec.Rec.Fail = nil
			}
			res, code, err := Run(name, c, src)
			if err != nil {
				t.Fatal(err)
			}
			got := Summarize(res, code)
			if *update {
				if c.DropEPSS {
					rec.Rec.EPSS = map[string]sources.EPSSScore{}
				}
				if err := rec.Rec.Save(filepath.Join(Dir, name, "recording.json")); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.MarshalIndent(got, "", "  ")
				if err := os.WriteFile(filepath.Join(Dir, name, "expected.json"), append(raw, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := LoadExpected(name)
			if err != nil {
				t.Fatal(err)
			}
			if d := Diff(want, got); d != "" {
				t.Errorf("the live sources now differ from the recording:\n%s", d)
			}
		})
	}
}

// noScores hides EPSS scores, for a case that stands for an advisory EPSS has not scored yet. The
// live call is still made, so the recording lists the CVEs as asked.
type noScores struct{ inner sources.EPSS }

func (n noScores) Scores(ctx context.Context, cves []string) (map[string]sources.EPSSScore, error) {
	if _, err := n.inner.Scores(ctx, cves); err != nil {
		return nil, err
	}
	return map[string]sources.EPSSScore{}, nil
}

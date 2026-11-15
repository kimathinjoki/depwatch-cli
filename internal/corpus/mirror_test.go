package corpus

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/mirror"
	"github.com/kimathinjoki/watchdep-cli/internal/sources"
)

// The mirror answers the same advisory ids as the recorded OSV API for every corpus case: the
// server's matcher and the live API agree on what each recorded version is affected by.
func TestMirrorAgreesWithRecordedAPI(t *testing.T) {
	for _, name := range Cases {
		rec, err := sources.LoadRecording(filepath.Join(Dir, name, "recording.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.OSVQueries) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			// One export archive per ecosystem folder, holding every recorded advisory.
			byEco := map[string]map[string]*sources.Vuln{}
			for id, v := range rec.OSVVulns {
				for _, a := range v.Affected {
					base := mirror.Base(a.Package.Ecosystem)
					if byEco[base] == nil {
						byEco[base] = map[string]*sources.Vuln{}
					}
					byEco[base][id] = v
				}
			}
			archives := map[string][]byte{}
			for base, vs := range byEco {
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				for id, v := range vs {
					w, _ := zw.Create(id + ".json")
					_ = json.NewEncoder(w).Encode(v)
				}
				_ = zw.Close()
				archives[base] = buf.Bytes()
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				base := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/all.zip")
				if b, ok := archives[base]; ok {
					_, _ = w.Write(b)
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			dir := t.TempDir()
			s := &mirror.Syncer{Dir: dir, BaseURL: srv.URL}
			for base := range archives {
				if _, err := s.Sync(context.Background(), base); err != nil {
					t.Fatal(err)
				}
			}
			osv := sources.NewMirrorOSV(dir)
			defer osv.R.Close()
			for key, want := range rec.OSVQueries {
				parts := strings.SplitN(key, "|", 3)
				q := sources.Query{Ecosystem: parts[0], Name: parts[1], Version: parts[2]}
				if len(want) == 0 {
					continue // an ecosystem with no advisories at all has no archive to sync
				}
				got, err := osv.Query(context.Background(), []sources.Query{q})
				if err != nil {
					t.Fatal(err)
				}
				w := append([]string{}, want...)
				sort.Strings(w)
				if !slices.Equal(got[key], w) {
					t.Errorf("%s: mirror %v, API %v", key, got[key], w)
				}
			}
		})
	}
}

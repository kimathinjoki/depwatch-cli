package sources

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kimathinjoki/watchdep-cli/internal/mirror"
)

// mirrorAt builds a mirror holding one npm advisory, synced at the given time, with the given last error.
func mirrorAt(t *testing.T, synced time.Time, lastError string) string {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("MAL-1.json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "MAL-1", "affected": []any{map[string]any{
		"package": map[string]any{"ecosystem": "npm", "name": "evil"}, "versions": []string{"1.0.0"}}}})
	_ = zw.Close()
	_ = f.Close()
	s := &mirror.Syncer{Dir: dir, Now: func() time.Time { return synced }}
	if _, err := s.Import("npm", archive); err != nil {
		t.Fatal(err)
	}
	if lastError != "" {
		st, _ := mirror.ReadState(dir, "npm")
		st.LastError = lastError
		raw, _ := json.Marshal(st)
		_ = os.WriteFile(filepath.Join(dir, "npm", "state.json"), raw, 0o644)
	}
	return dir
}

// A mirror older than its limit, or whose last sync failed, is a stale source: it still answers from
// its last good copy (a finding is never hidden), and it is reported as a gap.
func TestStaleMirrorIsAGap(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	q := []Query{{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}}
	for _, tc := range []struct {
		name   string
		synced time.Time
		err    string
		want   string
	}{
		{"fresh", now.Add(-time.Hour), "", ""},
		{"old", now.Add(-30 * time.Hour), "", "30 hours"},
		{"failed", now.Add(-time.Hour), "HTTP 503", "HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMirrorOSV(mirrorAt(t, tc.synced, tc.err))
			defer m.R.Close()
			m.MaxAge, m.Now = 24*time.Hour, func() time.Time { return now }
			ids, err := m.Query(context.Background(), q)
			if err != nil || len(ids[q[0].Key()]) != 1 {
				t.Fatalf("the last good copy must still answer: %v %v", ids, err)
			}
			gaps := m.Gaps()
			if tc.want == "" {
				if len(gaps) != 0 {
					t.Fatalf("a fresh mirror is no gap: %+v", gaps)
				}
				return
			}
			if len(gaps) != 1 || !strings.Contains(gaps[0].Why, tc.want) || !strings.Contains(gaps[0].What, "npm") {
				t.Fatalf("%+v", gaps)
			}
		})
	}
}

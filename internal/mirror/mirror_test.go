package mirror

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
)

// zipOf builds an export archive holding the given entries.
func zipOf(t testing.TB, entries map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for id, e := range entries {
		w, err := zw.Create(id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func entry(id, eco, name string, ranges []map[string]any, versions ...string) map[string]any {
	return map[string]any{"id": id, "affected": []any{map[string]any{
		"package": map[string]any{"ecosystem": eco, "name": name}, "ranges": ranges, "versions": versions}}}
}

func events(evs ...map[string]string) []map[string]any {
	var out []any
	for _, e := range evs {
		out = append(out, e)
	}
	return []map[string]any{{"type": "ECOSYSTEM", "events": out}}
}

func serve(t *testing.T, archives map[string][]byte) (*httptest.Server, *atomic.Int32) {
	var fail atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() == 1 {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		eco := filepath.Base(filepath.Dir(r.URL.Path))
		if r.Header.Get("If-Modified-Since") == "Thu, 12 Nov 2026 00:00:00 GMT" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		b, ok := archives[eco]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Thu, 12 Nov 2026 00:00:00 GMT")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &fail
}

func TestRanges(t *testing.T) {
	archives := map[string][]byte{
		"RubyGems": zipOf(t, map[string]any{
			"GHSA-a": entry("GHSA-a", "RubyGems", "rack", events(map[string]string{"introduced": "2.0.0"}, map[string]string{"fixed": "2.2.6.3"})),
			"GHSA-b": entry("GHSA-b", "RubyGems", "rack", events(map[string]string{"introduced": "0"}, map[string]string{"last_affected": "2.1.0"})),
			"GHSA-c": entry("GHSA-c", "RubyGems", "rack", nil, "2.2.3"),
		}),
		"Debian": zipOf(t, map[string]any{
			"DEBIAN-CVE-1": entry("DEBIAN-CVE-1", "Debian:13", "xz-utils", events(map[string]string{"introduced": "0"}, map[string]string{"fixed": "5.6.1+really5.4.5-1"})),
		}),
	}
	srv, _ := serve(t, archives)
	dir := t.TempDir()
	s := &Syncer{Dir: dir, BaseURL: srv.URL}
	for _, e := range []string{"RubyGems", "Debian:13"} {
		if _, err := s.Sync(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	r := Open(dir)
	defer r.Close()
	for _, c := range []struct {
		eco, name, version string
		want               []string
	}{
		{"RubyGems", "rack", "2.2.3", []string{"GHSA-a", "GHSA-c"}}, // inside a range; listed explicitly
		{"RubyGems", "rack", "2.2.6.3", nil},                        // the fixed version is not affected
		{"RubyGems", "rack", "2.1.0", []string{"GHSA-a", "GHSA-b"}}, // at last_affected
		{"RubyGems", "rack", "2.1.1", []string{"GHSA-a"}},           // after last_affected
		{"RubyGems", "rack", "1.6.0", []string{"GHSA-b"}},
		{"Debian:13", "xz-utils", "5.6.1-1", []string{"DEBIAN-CVE-1"}},
		{"Debian:13", "xz-utils", "5.6.1+really5.4.5-1", nil},
		{"Debian:12", "xz-utils", "5.6.1-1", nil}, // Debian:12 does not match Debian:13 entries
	} {
		got, err := r.Affecting(c.eco, c.name, c.version)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %s %s: %v, want %v", c.eco, c.name, c.version, got, c.want)
		}
	}
	if _, err := r.Affecting("npm", "left-pad", "1.0.0"); err != ErrNotSynced {
		t.Fatalf("an ecosystem never synced must be ErrNotSynced, got %v", err)
	}
}

// A failed download leaves the previous archive and index in place and reports the failure; an
// unchanged export is not downloaded again.
func TestFailedSyncKeepsThePreviousCopy(t *testing.T) {
	srv, fail := serve(t, map[string][]byte{"npm": zipOf(t, map[string]any{
		"MAL-1": entry("MAL-1", "npm", "evil", events(map[string]string{"introduced": "0"})),
	})})
	dir := t.TempDir()
	s := &Syncer{Dir: dir, BaseURL: srv.URL}
	first, err := s.Sync(context.Background(), "npm")
	if err != nil || first.Entries != 1 {
		t.Fatalf("%+v %v", first, err)
	}
	again, err := s.Sync(context.Background(), "npm")
	if err != nil || again.Entries != 1 || again.LastError != "" {
		t.Fatalf("not modified: %+v %v", again, err)
	}
	fail.Store(1)
	st, err := s.Sync(context.Background(), "npm")
	if err == nil || st.LastError == "" || st.SyncedAt != again.SyncedAt {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "npm", "all.zip")); err != nil {
		t.Fatal("the previous archive was lost")
	}
	r := Open(dir)
	defer r.Close()
	if ids, _ := r.Affecting("npm", "evil", "1.0.0"); !slices.Equal(ids, []string{"MAL-1"}) {
		t.Fatalf("the previous index no longer answers: %v", ids)
	}
}

func TestBadArchiveIsRefused(t *testing.T) {
	srv, _ := serve(t, map[string][]byte{"PyPI": []byte("not a zip")})
	s := &Syncer{Dir: t.TempDir(), BaseURL: srv.URL}
	if st, err := s.Sync(context.Background(), "PyPI"); err == nil || st.SyncedAt != "" {
		t.Fatalf("%+v %v", st, err)
	}
}

// Withdrawn entries are answered, so the server can tell withdrawn from fixed.
func TestWithdrawnIsAnswered(t *testing.T) {
	w := entry("GHSA-w", "npm", "x", events(map[string]string{"introduced": "0"}))
	w["withdrawn"] = "2026-01-01T00:00:00Z"
	srv, _ := serve(t, map[string][]byte{"npm": zipOf(t, map[string]any{"GHSA-w": w})})
	dir := t.TempDir()
	if _, err := (&Syncer{Dir: dir, BaseURL: srv.URL}).Sync(context.Background(), "npm"); err != nil {
		t.Fatal(err)
	}
	r := Open(dir)
	defer r.Close()
	if ids, _ := r.Affecting("npm", "x", "1.0.0"); !slices.Equal(ids, []string{"GHSA-w"}) {
		t.Fatalf("%v", ids)
	}
}

func TestImportArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(path, zipOf(t, map[string]any{"GHSA-i": entry("GHSA-i", "npm", "x", nil, "1.0.0")}), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := (&Syncer{Dir: dir}).Import("npm", path)
	if err != nil || st.Entries != 1 || st.SyncedAt == "" {
		t.Fatalf("%+v %v", st, err)
	}
	r := Open(dir)
	defer r.Close()
	if ids, _ := r.Affecting("npm", "x", "1.0.0"); !slices.Equal(ids, []string{"GHSA-i"}) {
		t.Fatalf("%v", ids)
	}
}

func TestPackageListsEveryEntry(t *testing.T) {
	old := entry("GHSA-old", "npm", "x", events(map[string]string{"introduced": "0"}, map[string]string{"fixed": "1.0.0"}))
	later := entry("GHSA-new", "npm", "x", nil, "2.0.0")
	other := entry("GHSA-y", "npm", "y", nil, "1.0.0")
	srv, _ := serve(t, map[string][]byte{"npm": zipOf(t, map[string]any{"GHSA-old": old, "GHSA-new": later, "GHSA-y": other})})
	dir := t.TempDir()
	if _, err := (&Syncer{Dir: dir, BaseURL: srv.URL}).Sync(context.Background(), "npm"); err != nil {
		t.Fatal(err)
	}
	r := Open(dir)
	defer r.Close()
	got, err := r.Package("npm", "x")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, raw := range got {
		var e struct{ ID string }
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	if !slices.Equal(ids, []string{"GHSA-new", "GHSA-old"}) {
		t.Fatalf("every entry for x, whatever its versions, in id order: %v", ids)
	}
	if got, err := r.Package("npm", "absent"); err != nil || len(got) != 0 {
		t.Fatalf("an unknown package is an empty list: %v %v", got, err)
	}
	if _, err := r.Package("PyPI", "x"); err == nil {
		t.Fatal("an ecosystem the mirror does not hold is an error, never an empty list")
	}
}

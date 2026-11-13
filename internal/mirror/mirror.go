// Package mirror keeps a local copy of OSV's per-ecosystem exports and answers which advisories
// affect a package version from it, with no network.
//
// Layout of a mirror folder:
//
//	<dir>/<Ecosystem>/all.zip     OSV's export for the ecosystem, as downloaded
//	<dir>/<Ecosystem>/index.json  "<affected ecosystem>|<package name>" to the entry files naming it
//	<dir>/<Ecosystem>/state.json  when it last synced, how many entries, the last error
//
// The ecosystem folder is the part before any ":" (Debian holds Debian:11, Debian:12 and so on).
package mirror

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultBaseURL is where OSV publishes its exports.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// IndexVersion is the version of index.json's format.
const IndexVersion = 1

// State is what state.json records about one ecosystem.
type State struct {
	Ecosystem     string `json:"ecosystem"`
	SyncedAt      string `json:"synced_at,omitempty"`
	Entries       int    `json:"entries"`
	ArchiveBytes  int64  `json:"archive_bytes"`
	LastModified  string `json:"last_modified,omitempty"`
	LastAttemptAt string `json:"last_attempt_at"`
	LastError     string `json:"last_error,omitempty"`
}

// Index maps "<affected ecosystem>|<normalized name>" to entry file names in the archive.
type Index struct {
	Version  int                 `json:"version"`
	Packages map[string][]string `json:"packages"`
}

// Base returns the export folder for an ecosystem: the part before any ":".
func Base(ecosystem string) string {
	if i := strings.Index(ecosystem, ":"); i >= 0 {
		return ecosystem[:i]
	}
	return ecosystem
}

// NormalizeName folds a package name the way its ecosystem compares names.
func NormalizeName(ecosystem, name string) string {
	switch Base(ecosystem) {
	case "PyPI":
		s := strings.ToLower(name)
		s = strings.NewReplacer("_", "-", ".", "-").Replace(s)
		for strings.Contains(s, "--") {
			s = strings.ReplaceAll(s, "--", "-")
		}
		return s
	case "Packagist", "NuGet", "Hex", "Pub":
		return strings.ToLower(name)
	}
	return name
}

// Key is an index key.
func Key(ecosystem, name string) string { return ecosystem + "|" + NormalizeName(ecosystem, name) }

// Syncer downloads exports.
type Syncer struct {
	Dir       string
	BaseURL   string
	Client    *http.Client
	UserAgent string
	Now       func() time.Time
}

// Sync downloads one ecosystem's export when it changed and rebuilds its index. A failed download or
// a bad archive keeps the previous archive and index, records the error and returns it.
func (s *Syncer) Sync(ctx context.Context, ecosystem string) (State, error) {
	base := Base(ecosystem)
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	dir := filepath.Join(s.Dir, base)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return State{}, err
	}
	st, _ := ReadState(s.Dir, base)
	st.Ecosystem = base
	st.LastAttemptAt = now().UTC().Format(time.RFC3339)

	fail := func(err error) (State, error) {
		st.LastError = err.Error()
		_ = writeJSON(filepath.Join(dir, "state.json"), st)
		return st, err
	}

	baseURL := s.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u := baseURL + "/" + url.PathEscape(base) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fail(err)
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	_, statErr := os.Stat(filepath.Join(dir, "all.zip"))
	if st.LastModified != "" && statErr == nil {
		req.Header.Set("If-Modified-Since", st.LastModified)
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(fmt.Errorf("downloading %s: %w", base, err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		st.SyncedAt = now().UTC().Format(time.RFC3339)
		st.LastError = ""
		return st, writeJSON(filepath.Join(dir, "state.json"), st)
	case http.StatusOK:
	default:
		return fail(fmt.Errorf("downloading %s: the server answered %d", base, resp.StatusCode))
	}

	tmp := filepath.Join(dir, "all.zip.download")
	f, err := os.Create(tmp)
	if err != nil {
		return fail(err)
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fail(fmt.Errorf("downloading %s: %w", base, err))
	}
	idx, entries, err := BuildIndex(tmp)
	if err != nil {
		os.Remove(tmp)
		return fail(fmt.Errorf("the %s export is not a readable archive: %w", base, err))
	}
	if err := writeJSON(filepath.Join(dir, "index.json.new"), idx); err != nil {
		os.Remove(tmp)
		return fail(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "all.zip")); err != nil {
		return fail(err)
	}
	if err := os.Rename(filepath.Join(dir, "index.json.new"), filepath.Join(dir, "index.json")); err != nil {
		return fail(err)
	}
	st.SyncedAt = now().UTC().Format(time.RFC3339)
	st.Entries = entries
	st.ArchiveBytes = n
	st.LastModified = resp.Header.Get("Last-Modified")
	st.LastError = ""
	return st, writeJSON(filepath.Join(dir, "state.json"), st)
}

// Import installs an export archive already on disk (for a copy with no route to OSV, or a test),
// exactly as Sync installs a download.
func (s *Syncer) Import(ecosystem, archive string) (State, error) {
	base := Base(ecosystem)
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	dir := filepath.Join(s.Dir, base)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return State{}, err
	}
	st, _ := ReadState(s.Dir, base)
	st.Ecosystem = base
	st.LastAttemptAt = now().UTC().Format(time.RFC3339)
	fail := func(err error) (State, error) {
		st.LastError = err.Error()
		_ = writeJSON(filepath.Join(dir, "state.json"), st)
		return st, err
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		return fail(err)
	}
	tmp := filepath.Join(dir, "all.zip.download")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fail(err)
	}
	idx, entries, err := BuildIndex(tmp)
	if err != nil {
		os.Remove(tmp)
		return fail(fmt.Errorf("the %s archive is not readable: %w", base, err))
	}
	if err := writeJSON(filepath.Join(dir, "index.json.new"), idx); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "all.zip")); err != nil {
		return fail(err)
	}
	if err := os.Rename(filepath.Join(dir, "index.json.new"), filepath.Join(dir, "index.json")); err != nil {
		return fail(err)
	}
	st.SyncedAt = now().UTC().Format(time.RFC3339)
	st.Entries = entries
	st.ArchiveBytes = int64(len(raw))
	st.LastModified = ""
	st.LastError = ""
	return st, writeJSON(filepath.Join(dir, "state.json"), st)
}

// BuildIndex reads every entry of an export archive and indexes it by the packages it affects.
func BuildIndex(zipPath string) (*Index, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, err
	}
	defer zr.Close()
	idx := &Index{Version: IndexVersion, Packages: map[string][]string{}}
	entries := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f.Name, err)
		}
		var e struct {
			Affected []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"affected"`
		}
		err = json.NewDecoder(rc).Decode(&e)
		rc.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f.Name, err)
		}
		entries++
		seen := map[string]bool{}
		for _, a := range e.Affected {
			k := Key(a.Package.Ecosystem, a.Package.Name)
			if a.Package.Name == "" || seen[k] {
				continue
			}
			seen[k] = true
			idx.Packages[k] = append(idx.Packages[k], f.Name)
		}
	}
	if entries == 0 {
		return nil, 0, errors.New("the archive holds no entries")
	}
	for k := range idx.Packages {
		sort.Strings(idx.Packages[k])
	}
	return idx, entries, nil
}

// ReadState reads an ecosystem's state; a missing state is an ecosystem never synced.
func ReadState(dir, base string) (State, error) {
	var st State
	raw, err := os.ReadFile(filepath.Join(dir, base, "state.json"))
	if err != nil {
		return State{Ecosystem: base}, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}

// States lists every ecosystem folder's state.
func States(dir string) ([]State, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []State
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if st, err := ReadState(dir, e.Name()); err == nil {
			out = append(out, st)
		}
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

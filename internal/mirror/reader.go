package mirror

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/semantic"
)

// ErrNotSynced is returned for an ecosystem the mirror does not hold.
var ErrNotSynced = errors.New("not synced")

// Reader answers from a mirror folder. It is safe for concurrent use.
type Reader struct {
	Dir string

	mu    sync.Mutex
	eco   map[string]*ecoData
	where map[string]string // advisory id to the ecosystem folder holding it
}

type ecoData struct {
	idx   *Index
	zr    *zip.ReadCloser
	files map[string]*zip.File
	cache map[string]*Entry
	state State
}

// Entry is the part of an OSV entry the matcher reads, plus the raw JSON to pass on.
type Entry struct {
	ID       string `json:"id"`
	Withdraw string `json:"withdrawn,omitempty"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
				Limit        string `json:"limit,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	Raw json.RawMessage `json:"-"`
}

// Open opens a mirror folder for reading.
func Open(dir string) *Reader {
	return &Reader{Dir: dir, eco: map[string]*ecoData{}, where: map[string]string{}}
}

// Close releases the archives.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.eco {
		if e != nil && e.zr != nil {
			e.zr.Close()
		}
	}
	return nil
}

func (r *Reader) load(base string) (*ecoData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.eco[base]; ok {
		if e == nil {
			return nil, ErrNotSynced
		}
		return e, nil
	}
	st, err := ReadState(r.Dir, base)
	if err != nil || st.SyncedAt == "" {
		r.eco[base] = nil
		return nil, ErrNotSynced
	}
	raw, err := os.ReadFile(filepath.Join(r.Dir, base, "index.json"))
	if err != nil {
		r.eco[base] = nil
		return nil, ErrNotSynced
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil || idx.Version != IndexVersion {
		r.eco[base] = nil
		return nil, fmt.Errorf("the %s index is unreadable; sync it again", base)
	}
	zr, err := zip.OpenReader(filepath.Join(r.Dir, base, "all.zip"))
	if err != nil {
		r.eco[base] = nil
		return nil, fmt.Errorf("the %s archive is unreadable: %w", base, err)
	}
	files := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		files[f.Name] = f
	}
	e := &ecoData{idx: &idx, zr: zr, files: files, cache: map[string]*Entry{}, state: st}
	r.eco[base] = e
	return e, nil
}

// State returns the sync state of the folder holding an ecosystem; ok is false when it never synced.
func (r *Reader) State(ecosystem string) (State, bool) {
	e, err := r.load(Base(ecosystem))
	if err != nil {
		return State{}, false
	}
	return e.state, true
}

func (r *Reader) entry(base string, e *ecoData, file string) (*Entry, error) {
	r.mu.Lock()
	if en, ok := e.cache[file]; ok {
		r.mu.Unlock()
		return en, nil
	}
	f, ok := e.files[file]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s is indexed but missing from the %s archive", file, base)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(rc).Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var en Entry
	if err := json.Unmarshal(raw, &en); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	en.Raw = raw
	r.mu.Lock()
	e.cache[file] = &en
	r.where[en.ID] = base
	r.mu.Unlock()
	return &en, nil
}

// Affecting returns the ids of the advisories affecting one package version, in id order.
func (r *Reader) Affecting(ecosystem, name, version string) ([]string, error) {
	base := Base(ecosystem)
	e, err := r.load(base)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, file := range e.idx.Packages[Key(ecosystem, name)] {
		en, err := r.entry(base, e, file)
		if err != nil {
			return nil, err
		}
		// Withdrawn entries are answered too, so a server can tell withdrawn from fixed; watchdep gate
		// drops them when it builds findings.
		if Affects(en, ecosystem, name, version) {
			ids = append(ids, en.ID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Package returns every entry the mirror holds for one package, whatever versions they affect and
// withdrawn ones included, in id order. An ecosystem the mirror does not hold is an error.
func (r *Reader) Package(ecosystem, name string) ([]json.RawMessage, error) {
	base := Base(ecosystem)
	e, err := r.load(base)
	if err != nil {
		return nil, err
	}
	var entries []*Entry
	for _, file := range e.idx.Packages[Key(ecosystem, name)] {
		en, err := r.entry(base, e, file)
		if err != nil {
			return nil, err
		}
		entries = append(entries, en)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	out := make([]json.RawMessage, 0, len(entries))
	for _, en := range entries {
		out = append(out, en.Raw)
	}
	return out, nil
}

// Raw returns an advisory's full entry, from whichever ecosystem's archive holds it.
func (r *Reader) Raw(id string) (json.RawMessage, error) {
	r.mu.Lock()
	base, ok := r.where[id]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("advisory %s is not in the mirror", id)
	}
	e, err := r.load(base)
	if err != nil {
		return nil, err
	}
	en, err := r.entry(base, e, id+".json")
	if err != nil {
		return nil, err
	}
	return en.Raw, nil
}

// Affects evaluates an entry against one package version, as the OSV schema defines: a version listed
// in versions is affected; for ECOSYSTEM and SEMVER ranges, events are applied in version order and
// the version is affected after an introduced event at or below it until a fixed event at or below
// it, or a last_affected event below it. GIT ranges are not evaluated (no commit is known).
func Affects(en *Entry, ecosystem, name, version string) bool {
	norm := NormalizeName(ecosystem, name)
	for _, a := range en.Affected {
		if a.Package.Ecosystem != ecosystem || NormalizeName(ecosystem, a.Package.Name) != norm {
			continue
		}
		for _, v := range a.Versions {
			if v == version {
				return true
			}
		}
		for _, rg := range a.Ranges {
			parseEco := ecosystem
			switch rg.Type {
			case "SEMVER":
				parseEco = "npm"
			case "ECOSYSTEM":
			default:
				continue
			}
			pv := version
			if rg.Type == "SEMVER" {
				pv = strings.TrimPrefix(version, "v")
			}
			cur, err := semantic.Parse(pv, parseEco)
			if err != nil {
				continue
			}
			cmp := func(s string) (int, bool) {
				if rg.Type == "SEMVER" {
					s = strings.TrimPrefix(s, "v")
				}
				c, err := cur.CompareStr(s)
				return c, err == nil
			}
			type ev struct {
				kind, v string
			}
			var evs []ev
			limits := []string{}
			for _, e := range rg.Events {
				switch {
				case e.Introduced != "":
					evs = append(evs, ev{"introduced", e.Introduced})
				case e.Fixed != "":
					evs = append(evs, ev{"fixed", e.Fixed})
				case e.LastAffected != "":
					evs = append(evs, ev{"last_affected", e.LastAffected})
				case e.Limit != "":
					limits = append(limits, e.Limit)
				}
			}
			// Sort events by version; "0" is below everything.
			sort.SliceStable(evs, func(i, j int) bool {
				if evs[i].v == "0" {
					return evs[j].v != "0"
				}
				if evs[j].v == "0" {
					return false
				}
				vi, err := semantic.Parse(evs[i].v, parseEco)
				if err != nil {
					return false
				}
				c, err := vi.CompareStr(evs[j].v)
				return err == nil && c < 0
			})
			affected := false
			for _, e := range evs {
				switch e.kind {
				case "introduced":
					if e.v == "0" {
						affected = true
					} else if c, ok := cmp(e.v); ok && c >= 0 {
						affected = true
					}
				case "fixed":
					if c, ok := cmp(e.v); ok && c >= 0 {
						affected = false
					}
				case "last_affected":
					if c, ok := cmp(e.v); ok && c > 0 {
						affected = false
					}
				}
			}
			if affected && len(limits) > 0 {
				below := false
				for _, l := range limits {
					if l == "*" {
						below = true
					} else if c, ok := cmp(l); ok && c < 0 {
						below = true
					}
				}
				affected = below
			}
			if affected {
				return true
			}
		}
	}
	return false
}

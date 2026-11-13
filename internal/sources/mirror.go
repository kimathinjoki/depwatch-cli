package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kimathinjoki/depwatch-cli/internal/mirror"
)

// Gap is something a source could not answer for, without failing as a whole.
type Gap struct {
	What string
	Why  string
	// Ecosystem names the ecosystem left unchecked, when the gap is one.
	Ecosystem string
}

// GapReporter is a source that can leave part of a question unanswered and say which part.
type GapReporter interface {
	Gaps() []Gap
}

// MirrorOSV answers OSV questions from a local mirror (mirror.Reader), with no network. Queries in
// an ecosystem the mirror does not hold get no answer and are reported as gaps.
//
// With MaxAge set, an ecosystem whose last good sync is older than MaxAge, or whose last sync failed,
// is a stale source: its last good copy still answers (a finding is never hidden), and it is reported
// as a gap, so the check is incomplete.
type MirrorOSV struct {
	R      *mirror.Reader
	Now    func() time.Time
	MaxAge time.Duration

	mu       sync.Mutex
	unsynced map[string]int
	stale    map[string]string
}

// StaleAfter is how long a mirror may go with no good sync before gate treats it as stale: the
// server's rule for a stalled source.
const StaleAfter = 24 * time.Hour

// NewMirrorOSV opens a mirror folder.
func NewMirrorOSV(dir string) *MirrorOSV {
	return &MirrorOSV{R: mirror.Open(dir), unsynced: map[string]int{}, stale: map[string]string{}}
}

// Query answers every query in a synced ecosystem.
func (m *MirrorOSV) Query(_ context.Context, qs []Query) (map[string][]string, error) {
	out := map[string][]string{}
	for _, q := range qs {
		ids, err := m.R.Affecting(q.Ecosystem, q.Name, q.Version)
		if errors.Is(err, mirror.ErrNotSynced) {
			m.mu.Lock()
			m.unsynced[mirror.Base(q.Ecosystem)]++
			m.mu.Unlock()
			continue
		}
		if err != nil {
			return nil, &Error{Source: NameOSV, Err: fmt.Errorf("reading the mirror: %w", err)}
		}
		m.checkFresh(q.Ecosystem)
		if ids == nil {
			ids = []string{}
		}
		out[q.Key()] = ids
	}
	return out, nil
}

// Vuln reads an advisory from the mirror.
func (m *MirrorOSV) Vuln(_ context.Context, id string) (*Vuln, error) {
	raw, err := m.R.Raw(id)
	if err != nil {
		return nil, &Error{Source: NameOSV, Err: err}
	}
	var v Vuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, &Error{Source: NameOSV, Err: err}
	}
	return &v, nil
}

// checkFresh records an ecosystem as stale, once, when its last sync failed or its last good sync is
// older than MaxAge.
func (m *MirrorOSV) checkFresh(ecosystem string) {
	if m.MaxAge <= 0 {
		return
	}
	base := mirror.Base(ecosystem)
	m.mu.Lock()
	if m.stale == nil {
		m.stale = map[string]string{}
	}
	_, done := m.stale[base]
	m.mu.Unlock()
	if done {
		return
	}
	why := ""
	if st, ok := m.R.State(ecosystem); ok {
		now := time.Now
		if m.Now != nil {
			now = m.Now
		}
		synced, err := time.Parse(time.RFC3339, st.SyncedAt)
		switch {
		case st.LastError != "":
			why = fmt.Sprintf("the OSV mirror's last sync of %s failed (%s); it answers from the copy synced %s", base, st.LastError, st.SyncedAt)
		case err != nil:
			why = fmt.Sprintf("the OSV mirror's sync time for %s is unreadable (%q)", base, st.SyncedAt)
		case now().Sub(synced) > m.MaxAge:
			why = fmt.Sprintf("the OSV mirror has not synced %s for %d hours (last good sync %s); advisories published since are missing", base, int(now().Sub(synced).Hours()), st.SyncedAt)
		}
	}
	m.mu.Lock()
	m.stale[base] = why
	m.mu.Unlock()
}

// Gaps lists the ecosystems the mirror does not hold, with how many packages went unchecked, and the
// ecosystems it holds a stale copy of.
func (m *MirrorOSV) Gaps() []Gap {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ecos []string
	for e := range m.unsynced {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	var out []Gap
	for _, e := range ecos {
		out = append(out, Gap{
			What:      fmt.Sprintf("%d %s packages", m.unsynced[e], e),
			Why:       "the OSV mirror has not synced " + e + " yet",
			Ecosystem: e,
		})
	}
	var stale []string
	for e, why := range m.stale {
		if why != "" {
			stale = append(stale, e)
		}
	}
	sort.Strings(stale)
	for _, e := range stale {
		out = append(out, Gap{What: "OSV mirror for " + e + " (stale)", Why: m.stale[e]})
	}
	return out
}

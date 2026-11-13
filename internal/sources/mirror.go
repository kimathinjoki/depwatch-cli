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
}

// GapReporter is a source that can leave part of a question unanswered and say which part.
type GapReporter interface {
	Gaps() []Gap
}

// MirrorOSV answers OSV questions from a local mirror (mirror.Reader), with no network. Queries in
// an ecosystem the mirror does not hold get no answer and are reported as gaps.
type MirrorOSV struct {
	R   *mirror.Reader
	Now func() time.Time

	mu       sync.Mutex
	unsynced map[string]int
}

// NewMirrorOSV opens a mirror folder.
func NewMirrorOSV(dir string) *MirrorOSV {
	return &MirrorOSV{R: mirror.Open(dir), unsynced: map[string]int{}}
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

// Gaps lists the ecosystems the mirror does not hold, with how many packages went unchecked.
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
			What: fmt.Sprintf("%d %s packages", m.unsynced[e], e),
			Why:  "the OSV mirror has not synced " + e + " yet",
		})
	}
	return out
}

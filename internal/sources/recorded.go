package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Recording is a committed set of source answers. The recorded sources answer only from it: a
// query that was not recorded is an error, so a test can never pass by not looking.
type Recording struct {
	// OSVQueries maps a Query's Key to the advisory ids OSV returned.
	OSVQueries map[string][]string `json:"osv_queries"`
	OSVVulns   map[string]*Vuln    `json:"osv_vulns"`
	// KEV holds the catalogue entries for the CVEs asked about; CVEs absent here are not in KEV.
	KEV map[string]KEVEntry `json:"kev"`
	// KEVAsked lists every CVE the recording asked KEV about, so an unrecorded CVE fails.
	KEVAsked []string             `json:"kev_asked"`
	EPSS     map[string]EPSSScore `json:"epss"`
	// EPSSAsked lists every CVE the recording asked EPSS about.
	EPSSAsked []string `json:"epss_asked"`
	// Fail names sources that answer with an error, to test what a stalled source does.
	Fail []string `json:"fail,omitempty"`
}

// LoadRecording reads a recording file.
func LoadRecording(path string) (*Recording, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Recording
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// Save writes the recording with sorted keys.
func (r *Recording) Save(path string) error {
	sort.Strings(r.KEVAsked)
	sort.Strings(r.EPSSAsked)
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// Sources returns the three sources answering from the recording.
func (r *Recording) Sources() Set {
	fail := map[string]bool{}
	for _, f := range r.Fail {
		fail[f] = true
	}
	return Set{OSV: recordedOSV{r, fail[NameOSV]}, KEV: recordedKEV{r, fail[NameKEV]}, EPSS: recordedEPSS{r, fail[NameEPSS]}}
}

var errStalled = fmt.Errorf("timed out (recorded failure)")

type recordedOSV struct {
	r    *Recording
	fail bool
}

func (o recordedOSV) Query(_ context.Context, qs []Query) (map[string][]string, error) {
	if o.fail {
		return nil, &Error{Source: NameOSV, Err: errStalled}
	}
	out := map[string][]string{}
	for _, q := range qs {
		ids, ok := o.r.OSVQueries[q.Key()]
		if !ok {
			return nil, &Error{Source: NameOSV, Err: fmt.Errorf("query %s is not in the recording", q.Key())}
		}
		out[q.Key()] = ids
	}
	return out, nil
}

func (o recordedOSV) Vuln(_ context.Context, id string) (*Vuln, error) {
	if o.fail {
		return nil, &Error{Source: NameOSV, Err: errStalled}
	}
	v, ok := o.r.OSVVulns[id]
	if !ok {
		return nil, &Error{Source: NameOSV, Err: fmt.Errorf("advisory %s is not in the recording", id)}
	}
	return v, nil
}

type recordedKEV struct {
	r    *Recording
	fail bool
}

func (k recordedKEV) Lookup(_ context.Context, cves []string) (map[string]KEVEntry, error) {
	if k.fail {
		return nil, &Error{Source: NameKEV, Err: errStalled}
	}
	asked := map[string]bool{}
	for _, c := range k.r.KEVAsked {
		asked[c] = true
	}
	out := map[string]KEVEntry{}
	for _, c := range cves {
		if !asked[c] {
			return nil, &Error{Source: NameKEV, Err: fmt.Errorf("%s is not in the recording", c)}
		}
		if e, ok := k.r.KEV[c]; ok {
			out[c] = e
		}
	}
	return out, nil
}

type recordedEPSS struct {
	r    *Recording
	fail bool
}

func (e recordedEPSS) Scores(_ context.Context, cves []string) (map[string]EPSSScore, error) {
	if e.fail {
		return nil, &Error{Source: NameEPSS, Err: errStalled}
	}
	asked := map[string]bool{}
	for _, c := range e.r.EPSSAsked {
		asked[c] = true
	}
	out := map[string]EPSSScore{}
	for _, c := range cves {
		if !asked[c] {
			return nil, &Error{Source: NameEPSS, Err: fmt.Errorf("%s is not in the recording", c)}
		}
		if s, ok := e.r.EPSS[c]; ok {
			out[c] = s
		}
	}
	return out, nil
}

// Recorder wraps live sources and writes down every answer, to build a recording.
type Recorder struct {
	Live Set
	Rec  *Recording
	mu   sync.Mutex
}

// NewRecorder starts an empty recording over live sources.
func NewRecorder(live Set) *Recorder {
	return &Recorder{Live: live, Rec: &Recording{
		OSVQueries: map[string][]string{}, OSVVulns: map[string]*Vuln{},
		KEV: map[string]KEVEntry{}, EPSS: map[string]EPSSScore{},
	}}
}

// Sources returns sources that answer live and record.
func (rc *Recorder) Sources() Set {
	return Set{OSV: recOSV{rc}, KEV: recKEV{rc}, EPSS: recEPSS{rc}}
}

type recOSV struct{ rc *Recorder }

func (o recOSV) Query(ctx context.Context, qs []Query) (map[string][]string, error) {
	out, err := o.rc.Live.OSV.Query(ctx, qs)
	if err == nil {
		o.rc.mu.Lock()
		defer o.rc.mu.Unlock()
		for k, v := range out {
			o.rc.Rec.OSVQueries[k] = v
		}
	}
	return out, err
}

func (o recOSV) Vuln(ctx context.Context, id string) (*Vuln, error) {
	v, err := o.rc.Live.OSV.Vuln(ctx, id)
	if err == nil {
		o.rc.mu.Lock()
		defer o.rc.mu.Unlock()
		o.rc.Rec.OSVVulns[id] = v
	}
	return v, err
}

type recKEV struct{ rc *Recorder }

func (k recKEV) Lookup(ctx context.Context, cves []string) (map[string]KEVEntry, error) {
	out, err := k.rc.Live.KEV.Lookup(ctx, cves)
	if err == nil {
		k.rc.mu.Lock()
		defer k.rc.mu.Unlock()
		k.rc.Rec.KEVAsked = append(k.rc.Rec.KEVAsked, cves...)
		for c, e := range out {
			k.rc.Rec.KEV[c] = e
		}
	}
	return out, err
}

type recEPSS struct{ rc *Recorder }

func (e recEPSS) Scores(ctx context.Context, cves []string) (map[string]EPSSScore, error) {
	out, err := e.rc.Live.EPSS.Scores(ctx, cves)
	if err == nil {
		e.rc.mu.Lock()
		defer e.rc.mu.Unlock()
		e.rc.Rec.EPSSAsked = append(e.rc.Rec.EPSSAsked, cves...)
		for c, s := range out {
			e.rc.Rec.EPSS[c] = s
		}
	}
	return out, err
}

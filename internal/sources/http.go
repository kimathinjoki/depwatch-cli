package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Default endpoints.
const (
	DefaultOSVURL  = "https://api.osv.dev"
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://api.first.org/data/v1/epss"
)

// OSVBatchLimit is the most queries OSV accepts in one querybatch call.
const OSVBatchLimit = 1000

// epssBatch keeps the EPSS request URL well within common length limits.
const epssBatch = 100

func newClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

// Live returns the real sources. userAgent names the CLI and its version.
func Live(userAgent string, timeout time.Duration) Set {
	c := newClient(timeout)
	return Set{
		OSV:  &HTTPOSV{BaseURL: DefaultOSVURL, Client: c, UserAgent: userAgent},
		KEV:  &HTTPKEV{URL: DefaultKEVURL, Client: c, UserAgent: userAgent},
		EPSS: &HTTPEPSS{URL: DefaultEPSSURL, Client: c, UserAgent: userAgent},
	}
}

func getJSON(ctx context.Context, c *http.Client, ua, method, u string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("%s answered %d: %s", req.URL.Host, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// HTTPOSV reads OSV's public API.
type HTTPOSV struct {
	BaseURL   string
	Client    *http.Client
	UserAgent string

	mu    sync.Mutex
	cache map[string]*Vuln
}

type osvBatchQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Query sends the queries in batches of at most OSVBatchLimit, following page tokens.
func (o *HTTPOSV) Query(ctx context.Context, qs []Query) (map[string][]string, error) {
	out := make(map[string][]string, len(qs))
	type pending struct {
		q     Query
		token string
	}
	var work []pending
	seen := map[string]bool{}
	for _, q := range qs {
		if !seen[q.Key()] {
			seen[q.Key()] = true
			work = append(work, pending{q: q})
			out[q.Key()] = []string{}
		}
	}
	for len(work) > 0 {
		n := len(work)
		if n > OSVBatchLimit {
			n = OSVBatchLimit
		}
		batch := work[:n]
		work = work[n:]
		body := struct {
			Queries []osvBatchQuery `json:"queries"`
		}{}
		for _, p := range batch {
			bq := osvBatchQuery{Version: p.q.Version, PageToken: p.token}
			bq.Package.Ecosystem = p.q.Ecosystem
			bq.Package.Name = p.q.Name
			body.Queries = append(body.Queries, bq)
		}
		var resp osvBatchResponse
		if err := getJSON(ctx, o.Client, o.UserAgent, http.MethodPost, o.BaseURL+"/v1/querybatch", body, &resp); err != nil {
			return nil, &Error{Source: NameOSV, Err: err}
		}
		if len(resp.Results) != len(batch) {
			return nil, &Error{Source: NameOSV, Err: fmt.Errorf("asked %d queries, got %d answers", len(batch), len(resp.Results))}
		}
		for i, r := range resp.Results {
			k := batch[i].q.Key()
			for _, v := range r.Vulns {
				out[k] = appendUnique(out[k], v.ID)
			}
			if r.NextPageToken != "" {
				work = append(work, pending{q: batch[i].q, token: r.NextPageToken})
			}
		}
	}
	return out, nil
}

// Vuln reads one advisory, once per run.
func (o *HTTPOSV) Vuln(ctx context.Context, id string) (*Vuln, error) {
	o.mu.Lock()
	if o.cache == nil {
		o.cache = map[string]*Vuln{}
	}
	if v, ok := o.cache[id]; ok {
		o.mu.Unlock()
		return v, nil
	}
	o.mu.Unlock()
	var v Vuln
	if err := getJSON(ctx, o.Client, o.UserAgent, http.MethodGet, o.BaseURL+"/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		return nil, &Error{Source: NameOSV, Err: err}
	}
	o.mu.Lock()
	o.cache[id] = &v
	o.mu.Unlock()
	return &v, nil
}

// HTTPKEV reads CISA's catalogue once per run.
type HTTPKEV struct {
	URL       string
	Client    *http.Client
	UserAgent string

	once    sync.Once
	catalog map[string]KEVEntry
	err     error
}

// Lookup returns the catalogue entries for the CVEs that are in it.
func (k *HTTPKEV) Lookup(ctx context.Context, cves []string) (map[string]KEVEntry, error) {
	k.once.Do(func() {
		var feed struct {
			Vulnerabilities []KEVEntry `json:"vulnerabilities"`
		}
		if err := getJSON(ctx, k.Client, k.UserAgent, http.MethodGet, k.URL, nil, &feed); err != nil {
			k.err = &Error{Source: NameKEV, Err: err}
			return
		}
		if len(feed.Vulnerabilities) == 0 {
			k.err = &Error{Source: NameKEV, Err: fmt.Errorf("the catalogue was empty")}
			return
		}
		k.catalog = map[string]KEVEntry{}
		for _, e := range feed.Vulnerabilities {
			k.catalog[e.CVE] = e
		}
	})
	if k.err != nil {
		return nil, k.err
	}
	out := map[string]KEVEntry{}
	for _, c := range cves {
		if e, ok := k.catalog[c]; ok {
			out[c] = e
		}
	}
	return out, nil
}

// HTTPEPSS reads FIRST's EPSS API.
type HTTPEPSS struct {
	URL       string
	Client    *http.Client
	UserAgent string
}

// Scores returns the scores EPSS has; a CVE with no score yet is absent from the map.
func (e *HTTPEPSS) Scores(ctx context.Context, cves []string) (map[string]EPSSScore, error) {
	out := map[string]EPSSScore{}
	for start := 0; start < len(cves); start += epssBatch {
		end := start + epssBatch
		if end > len(cves) {
			end = len(cves)
		}
		u := e.URL + "?cve=" + url.QueryEscape(strings.Join(cves[start:end], ","))
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		if err := getJSON(ctx, e.Client, e.UserAgent, http.MethodGet, u, nil, &resp); err != nil {
			return nil, &Error{Source: NameEPSS, Err: err}
		}
		for _, d := range resp.Data {
			var p, pc float64
			fmt.Sscanf(d.EPSS, "%g", &p)
			fmt.Sscanf(d.Percentile, "%g", &pc)
			out[d.CVE] = EPSSScore{CVE: d.CVE, Probability: p, Percentile: pc, Date: d.Date}
		}
	}
	return out, nil
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

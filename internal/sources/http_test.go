package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Two thousand packages are queried in batches within OSV's limit, and every package gets an answer.
func TestOSVBatches(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []osvBatchQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		sizes = append(sizes, len(body.Queries))
		mu.Unlock()
		if len(body.Queries) > OSVBatchLimit {
			http.Error(w, "too many", http.StatusBadRequest)
			return
		}
		var out osvBatchResponse
		for _, q := range body.Queries {
			res := struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			}{}
			if q.Package.Name == "pkg-7" && q.PageToken == "" {
				res.Vulns = append(res.Vulns, struct {
					ID string `json:"id"`
				}{"GHSA-first"})
				res.NextPageToken = "more"
			} else if q.Package.Name == "pkg-7" {
				res.Vulns = append(res.Vulns, struct {
					ID string `json:"id"`
				}{"GHSA-second"})
			}
			out.Results = append(out.Results, res)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	o := &HTTPOSV{BaseURL: srv.URL, Client: srv.Client()}
	var qs []Query
	for i := 0; i < 2000; i++ {
		qs = append(qs, Query{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"})
	}
	got, err := o.Query(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2000 {
		t.Fatalf("%d answers for 2000 packages", len(got))
	}
	for _, s := range sizes {
		if s > OSVBatchLimit {
			t.Fatalf("a batch of %d", s)
		}
	}
	if len(sizes) != 3 { // 1000, 1000, and the one page-token follow up
		t.Fatalf("batches: %v", sizes)
	}
	if ids := got[qs[7].Key()]; strings.Join(ids, ",") != "GHSA-first,GHSA-second" {
		t.Fatalf("pages were not followed: %v", ids)
	}
}

// A source that times out or answers an error fails with an error that names it.
func TestSourceErrorsNameTheSource(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer broken.Close()
	quick := &http.Client{Timeout: 50 * time.Millisecond}

	_, err := (&HTTPOSV{BaseURL: slow.URL, Client: quick}).Query(context.Background(), []Query{{"npm", "a", "1"}})
	assertSource(t, err, NameOSV)
	_, err = (&HTTPKEV{URL: broken.URL, Client: broken.Client()}).Lookup(context.Background(), []string{"CVE-1"})
	assertSource(t, err, NameKEV)
	_, err = (&HTTPEPSS{URL: broken.URL, Client: broken.Client()}).Scores(context.Background(), []string{"CVE-1"})
	assertSource(t, err, NameEPSS)
}

func assertSource(t *testing.T, err error, name string) {
	t.Helper()
	se, ok := err.(*Error)
	if !ok || se.Source != name {
		t.Fatalf("want an error naming %s, got %v", name, err)
	}
}

// A CVE listed in the KEV catalogue is returned with the date it was added.
func TestKEVLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","vulnerabilityName":"Log4j"}]}`)
	}))
	defer srv.Close()
	k := &HTTPKEV{URL: srv.URL, Client: srv.Client()}
	got, err := k.Lookup(context.Background(), []string{"CVE-2021-44228", "CVE-2020-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-2021-44228"].DateAdded != "2021-12-10" {
		t.Fatalf("%+v", got)
	}
}

func TestEPSSBatchesAndParses(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		cves := strings.Split(r.URL.Query().Get("cve"), ",")
		var data []map[string]string
		for _, c := range cves {
			data = append(data, map[string]string{"cve": c, "epss": "0.25", "percentile": "0.9", "date": "2026-11-12"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer srv.Close()
	var cves []string
	for i := 0; i < 250; i++ {
		cves = append(cves, fmt.Sprintf("CVE-2026-%d", i))
	}
	got, err := (&HTTPEPSS{URL: srv.URL, Client: srv.Client()}).Scores(context.Background(), cves)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(got) != 250 || got["CVE-2026-3"].Probability != 0.25 {
		t.Fatalf("calls %d, got %d", calls, len(got))
	}
}

func TestRecordedFailsOnAnythingUnrecorded(t *testing.T) {
	r := &Recording{OSVQueries: map[string][]string{}, OSVVulns: map[string]*Vuln{}}
	s := r.Sources()
	if _, err := s.OSV.Query(context.Background(), []Query{{"npm", "a", "1"}}); err == nil {
		t.Fatal("an unrecorded query must fail")
	}
	if _, err := s.KEV.Lookup(context.Background(), []string{"CVE-1"}); err == nil {
		t.Fatal("an unrecorded KEV lookup must fail")
	}
}

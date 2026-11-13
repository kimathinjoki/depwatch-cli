package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestFixOpensOnePullRequestAndNeverMerges(t *testing.T) {
	remote := t.TempDir()
	git(t, remote, "init", "--bare")
	repo := t.TempDir()
	git(t, repo, "init")
	_ = os.WriteFile(filepath.Join(repo, "requirements.txt"), []byte("django==4.2.0\n"), 0o644)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "init")
	git(t, repo, "remote", "add", "origin", remote)
	git(t, repo, "push", "origin", "main")

	var mu sync.Mutex
	var ghCalls []string
	prOpen := false
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ghCalls = append(ghCalls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/o/r/pulls":
			if prOpen {
				_, _ = w.Write([]byte(`[{"number":5,"html_url":"https://gh/o/r/pull/5","state":"open"}]`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		case r.Method == "POST" && r.URL.Path == "/repos/o/r/pulls":
			prOpen = true
			_, _ = w.Write([]byte(`{"number":5,"html_url":"https://gh/o/r/pull/5","state":"open"}`))
		case r.Method == "PATCH":
			_, _ = w.Write([]byte(`{"number":5,"html_url":"https://gh/o/r/pull/5","state":"open"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer gh.Close()

	var reported []map[string]any
	fixes := `{"part":"api","production_branch":"main","fixes":[{"finding_id":9,"primary_id":"CVE-2023-31047","ids":["CVE-2023-31047"],"level":"high",
	  "summary":"bypass","reason":"high","labels":[],"url":"https://dw/findings/9",
	  "targets":[{"kind":"package","ecosystem":"PyPI","name":"django","version":"4.2.0","fix":"4.2.2","relation":"unknown","paths":[],"source_file":"requirements.txt"}]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/fixes":
			_, _ = w.Write([]byte(fixes))
		case "/api/v1/fix_pull_requests":
			raw, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			reported = append(reported, m)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	env := Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(k string) string {
		return map[string]string{"DEPWATCH_SERVER": srv.URL, "DEPWATCH_TOKEN": "t", "GITHUB_TOKEN": "ghs", "GITHUB_REPOSITORY": "o/r", "GITHUB_API_URL": gh.URL}[k]
	}}
	var out strings.Builder
	env.Stdout = &out
	if code := Run([]string{"fix", repo}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if len(reported) != 1 || reported[0]["number"] != float64(5) || reported[0]["state"] != "open" || reported[0]["strategy"] != "direct" {
		t.Fatalf("%v", reported)
	}
	if got := git(t, remote, "show", "depwatch/cve-2023-31047-api:requirements.txt"); got != "django==4.2.2" {
		t.Fatalf("pushed %q", got)
	}
	if git(t, repo, "rev-parse", "--abbrev-ref", "HEAD") != "main" {
		t.Fatal("left on the fix branch")
	}
	// A second run while no pull request is recorded on the server updates the open one: never two.
	if code := Run([]string{"fix", repo}, env); code != 0 {
		t.Fatalf("second run: exit %d %s", code, out.String())
	}
	posts := 0
	for _, c := range ghCalls {
		if strings.HasPrefix(c, "POST /repos/o/r/pulls") {
			posts++
		}
		if strings.Contains(c, "/merge") {
			t.Fatalf("depwatch called merge: %v", ghCalls)
		}
	}
	if posts != 1 {
		t.Fatalf("%d pull requests opened: %v", posts, ghCalls)
	}
}

func TestDeployed(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"production_rule":"last deployed commit abc1234","inventoried":false,"message":"No inventory of abc1234 yet"}`))
	}))
	defer srv.Close()
	var out strings.Builder
	code := Run([]string{"deployed", "--sha", "abc1234def"}, Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string {
		return map[string]string{"DEPWATCH_SERVER": srv.URL, "DEPWATCH_TOKEN": "t"}[k]
	}})
	if code != 0 || got["commit"] != "abc1234def" || !strings.Contains(out.String(), "No inventory") {
		t.Fatalf("%d %v %s", code, got, out.String())
	}
}

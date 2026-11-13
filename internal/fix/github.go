package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Git runs git in the repository, as depwatch when no identity is configured.
type Git struct {
	Dir string
}

func (g Git) run(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-c", "user.name=" + identity(ctx, g.Dir, "user.name", "depwatch"),
		"-c", "user.email=" + identity(ctx, g.Dir, "user.email", "depwatch@users.noreply.github.com")}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = g.Dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func identity(ctx context.Context, dir, key, fallback string) string {
	cmd := exec.CommandContext(ctx, "git", "config", key)
	cmd.Dir = dir
	if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) != "" {
		return strings.TrimSpace(string(out))
	}
	return fallback
}

// Branch starts (or resets) a fix branch from base.
func (g Git) Branch(ctx context.Context, branch, base string) error {
	_, err := g.run(ctx, "checkout", "-B", branch, base)
	return err
}

// CommitAndPush commits tracked changes and pushes the branch. Returns false when nothing changed.
func (g Git) CommitAndPush(ctx context.Context, branch, message string) (bool, error) {
	if _, err := g.run(ctx, "add", "-u"); err != nil {
		return false, err
	}
	if out, _ := g.run(ctx, "status", "--porcelain", "--untracked-files=no"); out == "" {
		return false, nil
	}
	if _, err := g.run(ctx, "commit", "-m", message); err != nil {
		return false, err
	}
	_, err := g.run(ctx, "push", "--force-with-lease", "origin", branch)
	return err == nil, err
}

func (g Git) Checkout(ctx context.Context, ref string) error {
	_, err := g.run(ctx, "checkout", ref)
	return err
}

func (g Git) Current(ctx context.Context) (string, error) {
	return g.run(ctx, "rev-parse", "--abbrev-ref", "HEAD")
}

// GitHub opens and reads pull requests with the repository's own token. It has no merge call: depwatch
// never merges.
type GitHub struct {
	API   string // https://api.github.com
	Repo  string // owner/name
	Token string
	HTTP  *http.Client
}

// PullRequest is the part of GitHub's pull request depwatch reads.
type PullRequest struct {
	Number   int    `json:"number"`
	URL      string `json:"html_url"`
	State    string `json:"state"`
	MergedAt string `json:"merged_at"`
	Head     struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

// DepwatchState says open, merged or closed.
func (p PullRequest) DepwatchState() string {
	switch {
	case p.MergedAt != "":
		return "merged"
	case p.State == "closed":
		return "closed"
	}
	return "open"
}

func (h GitHub) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.API, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := h.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub answered %d for %s %s: %s", resp.StatusCode, method, path, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Upsert opens the pull request for a branch, or updates the open one: one per finding per part.
func (h GitHub) Upsert(ctx context.Context, branch, base, title, body string) (PullRequest, error) {
	owner := strings.Split(h.Repo, "/")[0]
	var existing []PullRequest
	if err := h.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls?state=open&head=%s:%s", h.Repo, owner, branch), nil, &existing); err != nil {
		return PullRequest{}, err
	}
	var pr PullRequest
	if len(existing) > 0 {
		err := h.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/pulls/%d", h.Repo, existing[0].Number), map[string]string{"title": title, "body": body}, &pr)
		return pr, err
	}
	err := h.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/pulls", h.Repo), map[string]any{"title": title, "head": branch, "base": base, "body": body, "maintainer_can_modify": true}, &pr)
	return pr, err
}

// Get reads a pull request's state.
func (h GitHub) Get(ctx context.Context, number int) (PullRequest, error) {
	var pr PullRequest
	err := h.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d", h.Repo, number), nil, &pr)
	return pr, err
}

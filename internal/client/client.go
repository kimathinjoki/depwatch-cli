// Package client talks to a depwatch server, and keeps the tokens `depwatch login` stores.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials are the stored logins, one token per server.
type Credentials struct {
	Default string            `json:"default"`
	Servers map[string]string `json:"servers"`
}

// CredentialsPath is where logins are stored: the user's config folder, readable only by the user.
func CredentialsPath() (string, error) {
	if p := os.Getenv("DEPWATCH_CREDENTIALS"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "depwatch", "credentials.json"), nil
}

// NormalizeServer trims a server URL to scheme and host and path, with no trailing slash.
func NormalizeServer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }

// LoadCredentials reads the stored logins; none stored is an empty set.
func LoadCredentials() (*Credentials, error) {
	p, err := CredentialsPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Credentials{Servers: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", p, err)
	}
	if c.Servers == nil {
		c.Servers = map[string]string{}
	}
	return &c, nil
}

// Save writes the logins with owner-only permissions.
func (c *Credentials) Save() error {
	p, err := CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Client posts to one server with one part's token.
type Client struct {
	Server    string
	Token     string
	HTTP      *http.Client
	UserAgent string
}

// ScanResponse is the server's answer to an inventory.
type ScanResponse struct {
	Part        string `json:"part"`
	Application string `json:"application"`
	InventoryID int64  `json:"inventory_id"`
	Production  bool   `json:"production"`
	URL         string `json:"url"`
	Message     string `json:"message"`
}

// ErrRefused is a token the server refused.
var ErrRefused = errors.New("the server refused the token")

// RejectedError is an inventory the server would not accept, with its reason.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return "the server rejected the inventory: " + e.Reason }

// UnreachableError is a server that did not answer, or answered with a server error.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return "the server did not answer: " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// PostInventory sends an inventory document.
func (c *Client) PostInventory(ctx context.Context, doc []byte) (*ScanResponse, error) {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, NormalizeServer(c.Server)+"/api/v1/inventories", bytes.NewReader(doc))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &UnreachableError{Err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, ErrRefused
	case resp.StatusCode == http.StatusUnprocessableEntity || resp.StatusCode == http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(body))
		}
		return nil, &RejectedError{Reason: e.Error}
	case resp.StatusCode >= 300:
		return nil, &UnreachableError{Err: fmt.Errorf("it answered %d", resp.StatusCode)}
	}
	var out ScanResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &UnreachableError{Err: fmt.Errorf("its answer was not JSON: %w", err)}
	}
	return &out, nil
}

// FindingsResponse is the part's open findings for the code check.
type FindingsResponse struct {
	Part            string            `json:"part"`
	SnippetsAllowed bool              `json:"snippets_allowed"`
	Findings        []json.RawMessage `json:"findings"`
}

// GetFindings fetches the token's part's open findings.
func (c *Client) GetFindings(ctx context.Context) (*FindingsResponse, error) {
	var out FindingsResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/findings", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostCodeChecks sends the code check's results.
func (c *Client) PostCodeChecks(ctx context.Context, body any) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "/api/v1/code_checks", raw, &out)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, NormalizeServer(c.Server)+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return &UnreachableError{Err: err}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrRefused
	case resp.StatusCode == http.StatusUnprocessableEntity || resp.StatusCode == http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &RejectedError{Reason: e.Error}
	case resp.StatusCode >= 300:
		return &UnreachableError{Err: fmt.Errorf("it answered %d", resp.StatusCode)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &UnreachableError{Err: fmt.Errorf("its answer was not JSON: %w", err)}
	}
	return nil
}

// GetFixes fetches the findings to open pull requests for.
func (c *Client) GetFixes(ctx context.Context, out any) error {
	return c.do(ctx, http.MethodGet, "/api/v1/fixes", nil, out)
}

// PostJSON posts a JSON body to a server path.
func (c *Client) PostJSON(ctx context.Context, path string, body any) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, path, raw, &out)
}

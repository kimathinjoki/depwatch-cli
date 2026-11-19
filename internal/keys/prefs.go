package keys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Prefs is the provider and model check --assist uses when none is named: chosen in the keys menu,
// kept beside the logins (no secret is in it).
type Prefs struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// LoadPrefs reads the preference from dir; none saved is empty.
func LoadPrefs(dir string) (Prefs, error) {
	var p Prefs
	raw, err := os.ReadFile(filepath.Join(dir, "assist.json"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(raw, &p)
}

// SavePrefs writes the preference to dir.
func SavePrefs(dir string, p Prefs) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "assist.json"), append(raw, '\n'), 0o600)
}

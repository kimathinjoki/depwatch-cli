// Package keys keeps the AI providers' keys that check --assist and models use, in the operating
// system's own store: the macOS Keychain, Windows Credential Manager, or the Secret Service (GNOME
// Keyring, KWallet) on Linux. watchdep never writes a key to a file of its own.
package keys

import (
	"errors"
	"runtime"

	"github.com/zalando/go-keyring"
)

// Service is the name the keys are filed under in the store; each key's account is its provider.
const Service = "watchdep"

// ErrNotFound is a provider with no key saved.
var ErrNotFound = errors.New("no key saved")

// Store keeps one key per provider.
type Store interface {
	Get(provider string) (string, error)
	Set(provider, key string) error
	Delete(provider string) error
}

// System is the operating system's store.
type System struct{}

func (System) Get(provider string) (string, error) {
	v, err := keyring.Get(Service, provider)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return v, err
}

func (System) Set(provider, key string) error { return keyring.Set(Service, provider, key) }

func (System) Delete(provider string) error {
	err := keyring.Delete(Service, provider)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Name is what the operating system calls its store, for messages.
func Name() string {
	switch runtime.GOOS {
	case "darwin":
		return "the macOS Keychain"
	case "windows":
		return "Windows Credential Manager"
	default:
		return "your keyring (Secret Service)"
	}
}

// Memory is a store in memory, for tests.
type Memory map[string]string

func (m Memory) Get(provider string) (string, error) {
	if v, ok := m[provider]; ok {
		return v, nil
	}
	return "", ErrNotFound
}

func (m Memory) Set(provider, key string) error { m[provider] = key; return nil }

func (m Memory) Delete(provider string) error {
	if _, ok := m[provider]; !ok {
		return ErrNotFound
	}
	delete(m, provider)
	return nil
}

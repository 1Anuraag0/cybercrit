package bypass

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const tokenFile = "bypass-token.json"

// Token represents a one-time signed bypass token.
type Token struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// Create generates a one-time bypass token with a TTL (in commits, mapped to hours).
// The token is stored in ~/.cybercrit/<repo>/bypass-token.json.
func Create(repoRoot, reason string, ttlHours int) (*Token, error) {
	if reason == "" {
		return nil, fmt.Errorf("bypass reason is required (use --reason)")
	}

	id, err := generateID()
	if err != nil {
		return nil, err
	}

	token := &Token{
		ID:        id,
		Reason:    reason,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour),
		Used:      false,
	}

	if err := writeToken(repoRoot, token); err != nil {
		return nil, err
	}

	return token, nil
}

// Consume checks for a valid bypass token, marks it as used, and returns it.
// Returns nil if no valid token exists (normal scan should proceed).
func Consume(repoRoot string) (*Token, error) {
	token, err := readToken(repoRoot)
	if err != nil {
		return nil, nil // no token file — normal flow
	}
	if token == nil {
		return nil, nil
	}

	// Check if already used
	if token.Used {
		// Clean up used token
		_ = removeTokenFile(repoRoot)
		return nil, nil
	}

	// Check if expired
	if time.Now().UTC().After(token.ExpiresAt) {
		_ = removeTokenFile(repoRoot)
		return nil, nil
	}

	// Mark as used and save
	token.Used = true
	if err := writeToken(repoRoot, token); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}

	return token, nil
}

func tokenPath(repoRoot string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	repoName := filepath.Base(repoRoot)
	dir := filepath.Join(home, ".cybercrit", repoName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create bypass dir: %w", err)
	}
	return filepath.Join(dir, tokenFile), nil
}

func writeToken(repoRoot string, token *Token) error {
	path, err := tokenPath(repoRoot)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func readToken(repoRoot string) (*Token, error) {
	path, err := tokenPath(repoRoot)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func removeTokenFile(repoRoot string) error {
	path, err := tokenPath(repoRoot)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return hex.EncodeToString(b), nil
}


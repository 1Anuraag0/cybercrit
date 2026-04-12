package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// FileName is the config file name looked up in the repo root.
const FileName = ".cybercrit.toml"

// Config holds cybercrit runtime configuration.
type Config struct {
	// Phase1 controls local static analysis behavior.
	Phase1 Phase1Config `toml:"phase1"`

	// Phase2 controls LLM-based analysis behavior.
	Phase2 Phase2Config `toml:"phase2"`

	// Filter controls which files are skipped.
	Filter FilterConfig `toml:"filter"`
}

// Phase1Config governs the local semgrep-based scanner.
type Phase1Config struct {
	Enabled bool `toml:"enabled"`
}

// Phase2Config governs the cloud LLM integration.
type Phase2Config struct {
	Enabled   bool   `toml:"enabled"`
	Provider  string `toml:"provider"`
	Model     string `toml:"model"`
	TimeoutS  int    `toml:"timeout_seconds"`
	MaxTokens int    `toml:"max_tokens"`
}

// FilterConfig controls file-level filtering before analysis.
type FilterConfig struct {
	// BlockedExtensions are file extensions that are never analyzed.
	BlockedExtensions []string `toml:"blocked_extensions"`

	// MaxFileSizeKB is the maximum file size in KB to analyze.
	MaxFileSizeKB int `toml:"max_file_size_kb"`
}

// Default returns a Config with sensible production defaults.
func Default() Config {
	return Config{
		Phase1: Phase1Config{
			Enabled: true,
		},
		Phase2: Phase2Config{
			Enabled:   true,
			Provider:  "groq",
			Model:     "llama-3.3-70b-versatile",
			TimeoutS:  5,
			MaxTokens: 4096,
		},
		Filter: FilterConfig{
			BlockedExtensions: []string{
				".lock", ".sum", ".min.js", ".min.css",
				".map", ".svg", ".png", ".jpg", ".jpeg",
				".gif", ".ico", ".woff", ".woff2", ".ttf",
				".eot", ".mp4", ".webm", ".pdf",
			},
			MaxFileSizeKB: 512,
		},
	}
}

// Load reads config from `.cybercrit.toml` in the given directory,
// falling back to defaults for any missing fields.
func Load(dir string) (Config, error) {
	cfg := Default()

	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil // no config file — use defaults
	}
	if err != nil {
		return cfg, err
	}

	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// IsBlocked returns true if the given file path has a blocked extension.
func (c *Config) IsBlocked(filePath string) bool {
	ext := filepath.Ext(filePath)
	for _, blocked := range c.Filter.BlockedExtensions {
		if ext == blocked {
			return true
		}
	}
	return false
}

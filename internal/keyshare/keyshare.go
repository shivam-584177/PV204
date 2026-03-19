package keyshare

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

// Load reads a tss-lib LocalPartySaveData from a JSON file on disk.
func Load(path string) (*keygen.LocalPartySaveData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyshare: read file %q: %w", path, err)
	}
	var save keygen.LocalPartySaveData
	if err := json.Unmarshal(data, &save); err != nil {
		return nil, fmt.Errorf("keyshare: unmarshal %q: %w", path, err)
	}
	return &save, nil
}

// Save writes a LocalPartySaveData to disk as JSON.
func Save(path string, data *keygen.LocalPartySaveData) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("keyshare: marshal: %w", err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("keyshare: write %q: %w", path, err)
	}
	return nil
}

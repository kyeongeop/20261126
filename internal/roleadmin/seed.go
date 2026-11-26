package roleadmin

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed testdata/seed.json
var defaultSeedJSON []byte

func LoadDefaultSeed() (Seed, error) {
	var seed Seed
	if err := json.Unmarshal(defaultSeedJSON, &seed); err != nil {
		return Seed{}, fmt.Errorf("decode default seed: %w", err)
	}
	return seed, nil
}

func NewDefaultService() (*Service, error) {
	seed, err := LoadDefaultSeed()
	if err != nil {
		return nil, err
	}
	return NewService(seed)
}

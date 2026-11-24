// Package dojo converts findings to and from DefectDojo "Generic Findings
// Import" JSON.
package dojo

import "github.com/chrobson/ramparteye/internal/model"

// Codec marshals findings to the Generic Findings JSON format
// ({"findings":[...]}, whitelisted keys only, unique_id_from_tool unique per
// file) and parses the same format back.
type Codec interface {
	Marshal(f []model.Finding) ([]byte, error)
	Unmarshal(b []byte) ([]model.Finding, error)
}

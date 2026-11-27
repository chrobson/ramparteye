package secret

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Clean trims a credential typed into a form or set in the environment and
// rejects control characters and values longer than maxLen bytes. what names
// the value in errors ("DefectDojo token"); errors never include the value.
func Clean(v, what string, maxLen int) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > maxLen {
		return "", fmt.Errorf("%s is longer than %d bytes", what, maxLen)
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return "", errors.New(what + " must not contain control characters")
	}
	return v, nil
}

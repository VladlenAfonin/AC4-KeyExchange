package common

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Returns n bytes of HKDF processed message m.
func Hkdf(m []byte, n int) ([]byte, error) {
	hash := sha256.New
	hkdf := hkdf.New(hash, m, nil, nil)

	result := make([]byte, n)

	if _, err := io.ReadFull(hkdf, result); err != nil {
		return nil, err
	}

	return result, nil
}

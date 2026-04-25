package shared

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	connIDHexLen = 16
	suffixHexLen = 8
)

// GenerateID creates a cryptographically random unique identifier.
func GenerateID() (string, error) {
	b := make([]byte, connIDHexLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateConnID creates a unique connection identifier.
func GenerateConnID() (string, error) {
	b := make([]byte, connIDHexLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating conn ID: %w", err)
	}
	s := make([]byte, suffixHexLen/2)
	if _, err := rand.Read(s); err != nil {
		return "", fmt.Errorf("generating conn ID suffix: %w", err)
	}
	return fmt.Sprintf("c%s%s", hex.EncodeToString(b), hex.EncodeToString(s)), nil
}

// IsChannelEntry returns true if the description matches the channel prefix.
func IsChannelEntry(description string) bool {
	return strings.HasPrefix(description, ChannelDescPrefix)
}

// HashToken returns SHA256(token) for use as an encryption key base.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// RandomInt returns a cryptographically random int in [0, max).
func RandomInt(max int64) (int64, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).SetInt64(max))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// DeriveKey produces a deterministic 32-byte key from the token hash, connID, and seq.
// Used by the Encryptor for per-frame key derivation.
func DeriveKey(tokenHash []byte, connID string, seq int64) []byte {
	h := sha256.New()
	hashInput := tokenHash
	if len(hashInput) > 16 {
		hashInput = hashInput[:16]
	}
	h.Write(hashInput)
	h.Write([]byte(connID))
	h.Write([]byte{
		byte(seq >> 56), byte(seq >> 48), byte(seq >> 40), byte(seq >> 32),
		byte(seq >> 24), byte(seq >> 16), byte(seq >> 8), byte(seq),
	})
	return h.Sum(nil)
}

// Package shared – encryption utilities.
//
// IMPORTANT SECURITY DISCLAIMER:
//
//	This package implements two encryption algorithms: XOR and AES-256-GCM.
//
//	XOR Encryption Limitations (AlgorithmXOR):
//	  - XOR is a stream cipher equivalent to a Vigenère cipher over bytes.
//	  - It is NOT cryptographically secure by modern standards.
//	  - Known-plaintext attack: if an attacker knows even part of the plaintext,
//	    they can recover the keystream and decrypt other packets encrypted with
//	    the same key. HTTPS metadata (TLS handshake patterns) is largely predictable.
//	  - Deterministic: same plaintext + same key = same ciphertext.
//	  - No authentication: ciphertext can be silently modified without detection.
//	  - Per-packet key rotation (different seq → different key) mitigates key reuse
//	    but does NOT fix the fundamental weakness of XOR as a cipher.
//
//	AES-256-GCM (AlgorithmAES):
//	  - Provides authenticated encryption (tampering is detectable).
//	  - Uses a random nonce per encryption, so identical plaintexts produce
//	    different ciphertexts.
//	  - Still NOT forward-secret: token leakage → all past traffic decryptable.
//
//	Neither algorithm:
//	  - Protects against GitHub itself reading Gist content.
//	  - Provides forward secrecy (past traffic is decryptable if token leaks).
//	  - Hides traffic metadata (connection timing, frequency, packet sizes).
//
//	Use this system only with full awareness of these limitations.
//	Do NOT tunnel sensitive data (passwords, credentials, private keys) through
//	this system.
package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptionAlgorithm specifies the encryption algorithm for tunnel data.
type EncryptionAlgorithm string

const (
	// AlgorithmXOR uses XOR with per-packet key rotation via key derivation.
	// Fast and lightweight, but NOT cryptographically secure.
	// For educational and testing purposes only.
	AlgorithmXOR EncryptionAlgorithm = "xor"

	// AlgorithmAES uses AES-256-GCM with per-packet key derivation and
	// a cryptographically random nonce. Provides authenticated encryption.
	// More secure than XOR but still not forward-secret.
	AlgorithmAES EncryptionAlgorithm = "aes"
)

// paddingBlockSize is the boundary to which plaintext is padded before encryption.
// Padding disguises the actual data size, making traffic analysis harder.
const paddingBlockSize = 255

// Encryptor handles encryption and decryption of tunnel payloads.
// Both client and server use the same token to derive identical keys,
// enabling symmetric encryption without explicit key exchange.
type Encryptor struct {
	algorithm EncryptionAlgorithm
	// tokenHash is SHA256(token). The raw token is never stored after this.
	tokenHash []byte
}

// NewEncryptor creates an Encryptor for the given algorithm and token.
// The token is hashed immediately; this struct does not store the raw token.
func NewEncryptor(algorithm EncryptionAlgorithm, token string) *Encryptor {
	return &Encryptor{
		algorithm: algorithm,
		tokenHash: HashToken(token),
	}
}

// Encrypt encrypts plaintext and returns the result as a base64-encoded string.
//
// The encryption key is derived per-packet from the token hash, connection ID,
// and sequence number. Both parties can independently derive the same key, so
// no key exchange is needed.
//
// Parameters:
//   - plaintext: raw bytes to encrypt (may be any length up to MaxChunkSize)
//   - connID:    connection identifier, used in key derivation
//   - seq:       sequence number, used for per-packet key rotation
//
// Returns "" if plaintext is empty (ACK-only packets carry no data).
func (e *Encryptor) Encrypt(plaintext []byte, connID string, seq int64) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	// Pad plaintext to nearest paddingBlockSize boundary.
	// This obscures the actual data size from traffic analysis.
	padded := padData(plaintext)

	key := DeriveKey(e.tokenHash, connID, seq)

	var (
		ciphertext []byte
		err        error
	)

	switch e.algorithm {
	case AlgorithmXOR:
		// WARNING: XOR is not cryptographically secure. See package doc for details.
		ciphertext, err = xorEncrypt(padded, key)
	case AlgorithmAES:
		ciphertext, err = aesGCMEncrypt(padded, key)
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %q", e.algorithm)
	}

	if err != nil {
		return "", fmt.Errorf("encrypting data (algo=%s, seq=%d): %w", e.algorithm, seq, err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext and returns the original plaintext.
// The connID and seq must exactly match those used during Encrypt for key derivation.
//
// Returns nil if encoded is empty (ACK-only packet).
func (e *Encryptor) Decrypt(encoded string, connID string, seq int64) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 ciphertext: %w", err)
	}

	key := DeriveKey(e.tokenHash, connID, seq)

	var plaintext []byte
	switch e.algorithm {
	case AlgorithmXOR:
		// XOR is its own inverse: XOR(XOR(plaintext, key), key) == plaintext
		plaintext, err = xorEncrypt(ciphertext, key)
	case AlgorithmAES:
		plaintext, err = aesGCMDecrypt(ciphertext, key)
	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %q", e.algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("decrypting data (algo=%s, seq=%d): %w", e.algorithm, seq, err)
	}

	return unpadData(plaintext)
}

// xorEncrypt performs XOR stream cipher encryption/decryption.
// The key is cycled by using key[i % len(key)] for each byte position.
//
// Because XOR is its own inverse, the same function encrypts and decrypts:
//
//	xorEncrypt(xorEncrypt(plaintext, key), key) == plaintext
//
// SECURITY WARNING: XOR is not a cryptographically secure cipher.
// See the package-level documentation for the full list of weaknesses.
func xorEncrypt(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("XOR encryption key must not be empty")
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM authenticated encryption.
//
// Output format: [12-byte nonce][ciphertext+16-byte auth tag]
// The nonce is randomly generated per call, so identical plaintexts produce
// different ciphertexts. The 16-byte auth tag ensures ciphertext integrity.
//
// Key must be ≥32 bytes; only the first 32 bytes are used (AES-256).
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM wrapper: %w", err)
	}

	// Generate a cryptographically random nonce.
	// IMPORTANT: Never reuse a nonce with the same key in AES-GCM.
	// Per-packet key derivation (different seq → different key) makes nonce
	// reuse extremely unlikely, but we still generate a fresh random nonce
	// for defence in depth.
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating AES-GCM nonce: %w", err)
	}

	// gcm.Seal prepends the nonce to the ciphertext output.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecrypt decrypts AES-256-GCM ciphertext produced by aesGCMEncrypt.
// Expects the nonce prepended to the ciphertext (as produced by aesGCMEncrypt).
// Returns an error if authentication fails (possible data tampering).
func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM wrapper: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, minimum %d",
			len(ciphertext), nonceSize+gcm.Overhead())
	}

	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		// Authentication failure: ciphertext may have been tampered with,
		// or the key is wrong (different token, connID, or seq).
		return nil, fmt.Errorf("AES-GCM authentication failed (tampering or wrong key): %w", err)
	}

	return plaintext, nil
}

// padData pads data to the nearest multiple of paddingBlockSize bytes.
// Uses PKCS#7-style padding: each padding byte contains the padding length.
//
// This obscures the actual payload size from traffic analysis observers.
// Minimum padding is paddingBlockSize bytes (even if data is already aligned).
//
// Example: 100-byte data → 256-byte padded (156 padding bytes, each = 0x9C)
func padData(data []byte) []byte {
	padLen := paddingBlockSize - (len(data) % paddingBlockSize)
	// Always add at least one full block of padding, never zero padding.
	if padLen == 0 {
		padLen = paddingBlockSize
	}
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// unpadData removes PKCS#7-style padding added by padData.
// Returns an error if the padding is invalid, which may indicate data corruption
// or an incorrect decryption key.
func unpadData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unpad empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > paddingBlockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding length %d (data length %d)", padLen, len(data))
	}

	// Verify all padding bytes have the correct value (defence against corruption)
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, fmt.Errorf("padding byte at position %d has value %d, expected %d",
				i, data[i], padLen)
		}
	}

	return data[:len(data)-padLen], nil
}

package tests

import (
	"bytes"
	"testing"

	"github.com/sartoopjj/vpn-over-github/shared"
)

func TestXORRoundtrip(t *testing.T) {
	enc := shared.NewEncryptor(shared.AlgorithmXOR, "ghp_testtoken1234567890")
	plain := []byte("hello, world! this is test data.")
	connID := "conn_abc123_1713792000_def456"

	encoded, err := enc.Encrypt(plain, connID, 1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded string")
	}

	decoded, err := enc.Decrypt(encoded, connID, 1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, decoded) {
		t.Errorf("roundtrip mismatch: got %q, want %q", decoded, plain)
	}
}

func TestAESRoundtrip(t *testing.T) {
	enc := shared.NewEncryptor(shared.AlgorithmAES, "ghp_testtoken1234567890")
	plain := []byte("AES-256-GCM test payload")
	connID := "conn_aes_test"

	encoded, err := enc.Encrypt(plain, connID, 42)
	if err != nil {
		t.Fatalf("Encrypt AES: %v", err)
	}
	decoded, err := enc.Decrypt(encoded, connID, 42)
	if err != nil {
		t.Fatalf("Decrypt AES: %v", err)
	}
	if !bytes.Equal(plain, decoded) {
		t.Errorf("AES roundtrip mismatch: got %q, want %q", decoded, plain)
	}
}

func TestKeyRotation(t *testing.T) {
	// Different seq numbers must produce different ciphertexts (XOR key rotation)
	enc := shared.NewEncryptor(shared.AlgorithmXOR, "ghp_testtoken1234567890")
	plain := []byte("same plaintext")
	connID := "conn_rotation_test"

	enc1, _ := enc.Encrypt(plain, connID, 1)
	enc2, _ := enc.Encrypt(plain, connID, 2)
	if enc1 == enc2 {
		t.Error("expected different ciphertexts for different seq numbers")
	}
}

func TestEncryptEmptyData(t *testing.T) {
	enc := shared.NewEncryptor(shared.AlgorithmXOR, "ghp_testtoken1234567890")
	result, err := enc.Encrypt(nil, "conn_test", 1)
	if err != nil {
		t.Fatalf("unexpected error on empty data: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for nil input, got %q", result)
	}
}

func TestDecryptEmpty(t *testing.T) {
	enc := shared.NewEncryptor(shared.AlgorithmXOR, "ghp_testtoken1234567890")
	result, err := enc.Decrypt("", "conn_test", 1)
	if err != nil {
		t.Fatalf("unexpected error on empty decrypt: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for empty decrypt, got %v", result)
	}
}

func TestEncryptLargeData(t *testing.T) {
	enc := shared.NewEncryptor(shared.AlgorithmXOR, "ghp_testtoken1234567890")
	plain := bytes.Repeat([]byte("A"), 8192)
	connID := "conn_large"

	encoded, err := enc.Encrypt(plain, connID, 100)
	if err != nil {
		t.Fatalf("Encrypt large: %v", err)
	}
	decoded, err := enc.Decrypt(encoded, connID, 100)
	if err != nil {
		t.Fatalf("Decrypt large: %v", err)
	}
	if !bytes.Equal(plain, decoded) {
		t.Error("large data roundtrip mismatch")
	}
}

func TestWrongKeyDecryptFails(t *testing.T) {
	enc1 := shared.NewEncryptor(shared.AlgorithmAES, "ghp_token_A_12345678901")
	enc2 := shared.NewEncryptor(shared.AlgorithmAES, "ghp_token_B_09876543210")
	plain := []byte("secret payload")
	connID := "conn_wrongkey"

	encoded, err := enc1.Encrypt(plain, connID, 1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Decrypting with wrong token should fail (AES-GCM authentication check)
	_, err = enc2.Decrypt(encoded, connID, 1)
	if err == nil {
		t.Error("expected error when decrypting with wrong token")
	}
}

func TestDeriveKeyDeterminism(t *testing.T) {
	tokenHash := shared.HashToken("ghp_testtoken")
	connID := "conn_determinism_test"

	k1 := shared.DeriveKey(tokenHash, connID, 5)
	k2 := shared.DeriveKey(tokenHash, connID, 5)
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKey must be deterministic for same inputs")
	}

	k3 := shared.DeriveKey(tokenHash, connID, 6)
	if bytes.Equal(k1, k3) {
		t.Error("DeriveKey must differ for different seq numbers")
	}
}

func TestMaskToken(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		{"ghp_abcdefghijklmnopqrst", "ghp_****qrst"},
		{"short", "****"},
		{"", "****"},
	}
	for _, tc := range cases {
		got := shared.MaskToken(tc.token)
		if got != tc.want {
			t.Errorf("MaskToken(%q) = %q, want %q", tc.token, got, tc.want)
		}
	}
}

package client

import "github.com/sartoopjj/vpn-over-github/shared"

// newEncryptor creates an Encryptor for the given token and algorithm.
// This wrapper exists so the client package can create encryptors using
// the shared library with its local Config type.
func newEncryptor(token string, algo string) *shared.Encryptor {
	return shared.NewEncryptor(shared.EncryptionAlgorithm(algo), token)
}

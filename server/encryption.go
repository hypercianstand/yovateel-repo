package server

import "github.com/sartoopjj/vpn-over-github/shared"

// newServerEncryptor creates an Encryptor for the given token and algorithm.
func newServerEncryptor(token string, algo string) *shared.Encryptor {
	return shared.NewEncryptor(shared.EncryptionAlgorithm(algo), token)
}

package crypto

import (
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

// DeriveKey derives a cryptographic key from a password using the Argon2id key derivation function.
//
// If no salt is provided (salt is empty), a random salt of ArgonSaltLen bytes will be generated.
// It returns the derived key, the salt used, and an error if salt generation fails.
func DeriveKey(password string, salt []byte, config ArgonConfig) (key, usedSalt []byte, err error) {
	if len(salt) == 0 {
		salt = make([]byte, config.SaltLen)
		_, err = rand.Read(salt)
		if err != nil {
			return nil, nil, err
		}
	}

	key = argon2.IDKey(
		[]byte(password),
		salt,
		config.Iterations,
		config.Memory,
		config.Parallelism,
		config.KeyLen,
	)

	return key, salt, nil
}

// Zero securely wipes the contents of the given byte slice by setting all bytes to zero.
//
// This is typically used to remove sensitive data like keys or passwords from memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

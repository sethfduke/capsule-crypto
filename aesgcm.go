package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AESGCMEncrypt encrypts the given plaintext using AES-GCM with the provided key.
//
// It returns the randomly generated nonce, the resulting ciphertext, and an error if encryption fails.
// The key should be either 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256 respectively.
func AESGCMEncrypt(key, plaintext []byte) (nonce, ct []byte, err error) {
	block, cipherErr := aes.NewCipher(key)
	if cipherErr != nil {
		return nil, nil, cipherErr
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, nil, gcmErr
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, ioErr := io.ReadFull(rand.Reader, nonce); ioErr != nil {
		return nil, nil, ioErr
	}
	ct = gcm.Seal(nil, nonce, plaintext, nil)

	return nonce, ct, nil
}

// AESGCMDecrypt decrypts the given ciphertext using AES-GCM with the provided key and nonce.
//
// It returns the decrypted plaintext or an error if decryption fails.
// The key must match the one used for encryption, and the nonce must be the same nonce used during encryption.
func AESGCMDecrypt(key, nonce, ct []byte) ([]byte, error) {
	block, cipherErr := aes.NewCipher(key)
	if cipherErr != nil {
		return nil, cipherErr
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, gcmErr
	}
	return gcm.Open(nil, nonce, ct, nil)
}

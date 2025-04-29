package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// EncryptPayload encrypts the given plaintext using AES-GCM with the provided data encryption key (DEK).
//
// It generates a random IV (nonce), computes an HMAC over the ciphertext for integrity protection,
// and returns the base64-encoded IV, base64-encoded HMAC, the ciphertext, and an error if encryption fails.
func EncryptPayload(dek, plaintext []byte) (ivB64, hmacB64 string, ciphertext []byte, err error) {
	iv, ct, encErr := AESGCMEncrypt(dek, plaintext)
	if encErr != nil {
		err = encErr
		return
	}

	mac := hmac.New(sha256.New, dek)
	mac.Write(ct)
	tag := mac.Sum(nil)

	ivB64 = ToBase64String(iv)
	hmacB64 = ToBase64String(tag)
	ciphertext = ct

	return ivB64, hmacB64, ciphertext, nil
}

// DecryptPayload verifies the HMAC of the ciphertext and decrypts it using AES-GCM with the provided data encryption key (DEK).
//
// It expects the base64-encoded IV and HMAC generated during encryption.
// If the HMAC verification fails, it returns an error without attempting decryption.
func DecryptPayload(dek []byte, ivB64, hmacB64 string, ciphertext []byte) ([]byte, error) {
	iv, b64Err := FromBase64String(ivB64)
	if b64Err != nil {
		return nil, b64Err
	}
	want, b64Err := FromBase64String(hmacB64)
	if b64Err != nil {
		return nil, b64Err
	}

	mac := hmac.New(sha256.New, dek)
	mac.Write(ciphertext)
	if !hmac.Equal(want, mac.Sum(nil)) {
		return nil, errors.New("HMAC verification failed")
	}

	return AESGCMDecrypt(dek, iv, ciphertext)
}

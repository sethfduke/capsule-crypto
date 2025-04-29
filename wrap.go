package crypto

import (
	"errors"
	"fmt"
)

// WrapDEKWithPassword wraps a data encryption key (DEK) using a password-derived key.
//
// It returns a VaultKeyWrapper containing the base64-encoded wrapped DEK, nonce, and salt.
// It returns an error if wrapping fails.
func WrapDEKWithPassword(password string, dek []byte, config ArgonConfig) (*VaultKeyWrapper, error) {
	salt, nonce, wrapped, dekRrr := WrapDEK(password, dek, config)
	if dekRrr != nil {
		return nil, dekRrr
	}

	return &VaultKeyWrapper{
		WrappedKey: wrapped,
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

// UnwrapDEKWithPassword unwraps and decrypts a data encryption key (DEK) from a VaultKeyWrapper using the provided password.
//
// It returns the plaintext DEK or an error if unwrapping fails.
func UnwrapDEKWithPassword(password string, v *VaultKeyWrapper, config ArgonConfig) ([]byte, error) {
	return UnwrapDEK(password, v.Salt, v.Nonce, v.WrappedKey, config)
}

// WrapDEK encrypts a data encryption key (DEK) using a password-derived key.
//
// It generates a random salt and nonce, derives a key from the password, encrypts the DEK with AES-GCM,
// and returns the base64-encoded salt, nonce, and ciphertext.
// It returns an error if the DEK is not 32 bytes or if encryption fails.
func WrapDEK(password string, dek []byte, config ArgonConfig) (saltB64, nonceB64, wrappedB64 string, err error) {
	if len(dek) != int(config.KeyLen) {
		err = errors.New(fmt.Sprintf("DEK must be %d bytes", config.KeyLen))
		return
	}

	pwKey, salt, deriveErr := DeriveKey(password, nil, config)
	if deriveErr != nil {
		err = deriveErr
		return
	}

	nonce, ct, encErr := AESGCMEncrypt(pwKey, dek)
	if encErr != nil {
		err = encErr
		return
	}

	saltB64 = ToBase64String(salt)
	nonceB64 = ToBase64String(nonce)
	wrappedB64 = ToBase64String(ct)

	return saltB64, nonceB64, wrappedB64, nil
}

// UnwrapDEK decrypts and unwraps a base64-encoded encrypted DEK using a password-derived key.
//
// It decodes the salt, nonce, and ciphertext from base64, derives the decryption key from the password and salt,
// and decrypts the DEK using AES-GCM.
// It returns an error if password verification fails or if the unwrapped DEK does not have the expected length.
func UnwrapDEK(password, saltB64, nonceB64, wrappedB64 string, config ArgonConfig) ([]byte, error) {
	salt, b64Err := FromBase64String(saltB64)
	if b64Err != nil {
		return nil, b64Err
	}

	nonce, b64Err := FromBase64String(nonceB64)
	if b64Err != nil {
		return nil, b64Err
	}

	ct, b64Err := FromBase64String(wrappedB64)
	if b64Err != nil {
		return nil, b64Err
	}

	pwKey, _, deriveErr := DeriveKey(password, salt, config)
	if deriveErr != nil {
		return nil, deriveErr
	}

	plain, decErr := AESGCMDecrypt(pwKey, nonce, ct)
	if decErr != nil {
		return nil, errors.New("password incorrect or data corrupted")
	}

	if len(plain) != int(config.KeyLen) {
		return nil, errors.New(fmt.Sprintf("unexpected DEK length, %d != %d", len(plain), config.KeyLen))
	}

	return plain, nil
}

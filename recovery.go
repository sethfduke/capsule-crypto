package crypto

import "fmt"

// WrapForRecovery encrypts the WrappedKey field of the given VaultKeyWrapper using a recovery public RSA key.
//
// The recovery public key must be provided in PEM-encoded format.
// The resulting encrypted key is base64-encoded and stored in the RecoveryWrapped field.
// It returns an error if encryption fails.
func WrapForRecovery(v *VaultKeyWrapper, password string, config ArgonConfig, pubPEM []byte) error {
	// First, get the raw DEK using the current password
	rawDEK, err := UnwrapDEK(password, v.Salt, v.Nonce, v.WrappedKey, config)
	if err != nil {
		return fmt.Errorf("unwrap failed during recovery setup: %w", err)
	}

	// Encrypt raw DEK with the recovery public key
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	encrypted, err := RSAEncrypt(pub, rawDEK)
	if err != nil {
		return err
	}

	v.RecoveryWrapped = ToBase64String(encrypted)
	return nil
}

// UnwrapWithRecovery decrypts the RecoveryWrapped field of a VaultKeyWrapper using a recovery private RSA key.
//
// The recovery private key must be provided in PEM-encoded format.
// It returns the decrypted wrapped key, which is still password-encrypted and must be separately unlocked by the caller.
// It returns an error if decryption fails.
func UnwrapWithRecovery(privPEM []byte, v *VaultKeyWrapper) ([]byte, error) {
	priv, parseErr := ParsePrivateKey(privPEM)
	if parseErr != nil {
		return nil, parseErr
	}

	wrapped, b64Err := FromBase64String(v.RecoveryWrapped)
	if b64Err != nil {
		return nil, b64Err
	}

	raw, decErr := RSADecrypt(priv, wrapped)
	if decErr != nil {
		return nil, decErr
	}

	return raw, nil
}

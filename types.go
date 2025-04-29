package crypto

// ArgonConfig holds tunable parameters for Argon2id key derivation.
type ArgonConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgonConfig provides reasonable defaults for secure key derivation.
var DefaultArgonConfig = ArgonConfig{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLen:     16,
	KeyLen:      32,
}

// VaultKeyWrapper represents an encrypted wrapper for a derived vault key.
//
// WrappedKey is the base64-encoded encrypted vault key.
// Nonce is the base64-encoded nonce used during encryption.
// Salt is the base64-encoded salt used for key derivation.
// RecoveryWrapped is an optional base64-encoded recovery-encrypted key (empty if recovery is disabled).
type VaultKeyWrapper struct {
	WrappedKey      string
	Nonce           string
	Salt            string
	RecoveryWrapped string
}

// ObjectMeta holds metadata for an encrypted object.
//
// Key is the base64-encoded object encryption key.
// IV is the base64-encoded initialization vector (nonce).
// HMAC is the base64-encoded HMAC for integrity verification.
// EncDataKey is the base64-encoded encrypted data key.
// Extra is an optional map for storing additional metadata.
type ObjectMeta struct {
	Key        string
	IV         string
	HMAC       string
	EncDataKey string
	Extra      map[string]any `json:"extra,omitempty"`
}

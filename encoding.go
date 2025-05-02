package crypto

import "encoding/base64"

// ToBase64String encodes the given byte slice into a base64 URL-safe string without padding.
//
// It uses the StdEncoding, which omits any '=' padding characters.
func ToBase64String(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// FromBase64String decodes a base64 URL-safe string without padding back into a byte slice.
//
// It expects the input string to be encoded using StdEncoding (no padding).
// It returns an error if the input is not a valid base64 encoding.
func FromBase64String(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

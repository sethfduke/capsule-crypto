// rsa.go
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenerateRSAKeyPair generates a new 2048-bit RSA key pair.
//
// It returns the public key and private key encoded in PEM format, and an error if key generation fails.
func GenerateRSAKeyPair() (pubPEM, privPEM []byte, err error) {
	priv, genErr := rsa.GenerateKey(rand.Reader, 2048)
	if genErr != nil {
		return
	}

	privPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})

	pubDER, marshErr := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if marshErr != nil {
		return
	}

	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return pubPEM, privPEM, marshErr
}

// ParsePublicKey parses a PEM-encoded RSA public key.
//
// It returns an *rsa.PublicKey or an error if parsing fails.
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key")
	}

	i, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return nil, parseErr
	}

	pub, ok := i.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA")
	}

	return pub, nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key.
//
// It returns an *rsa.PrivateKey or an error if parsing fails.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// RSAEncrypt encrypts data using the given RSA public key and OAEP with SHA-256.
//
// It returns the encrypted ciphertext or an error if encryption fails.
func RSAEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

// RSADecrypt decrypts data using the given RSA private key and OAEP with SHA-256.
//
// It returns the decrypted plaintext or an error if decryption fails.
func RSADecrypt(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
}

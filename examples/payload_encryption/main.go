package main

import (
	"crypto/rand"
	"fmt"

	"github.com/sethfduke/capsule-crypto"
)

func main() {
	config := crypto.DefaultArgonConfig

	// Generate a random DEK
	dek := make([]byte, config.KeyLen)
	_, err := rand.Read(dek)
	if err != nil {
		panic(err)
	}

	payload := []byte("Top secret document payload.")

	fmt.Println("Original Payload:", string(payload))

	// Encrypt the payload
	ivB64, hmacB64, ciphertext, err := crypto.EncryptPayload(dek, payload)
	if err != nil {
		panic(err)
	}

	fmt.Println("IV (base64):", ivB64)
	fmt.Println("HMAC (base64):", hmacB64)
	fmt.Println("Ciphertext (raw bytes):", ciphertext)

	// Decrypt the payload
	decrypted, err := crypto.DecryptPayload(dek, ivB64, hmacB64, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted Payload:", string(decrypted))

	// Verify
	if string(payload) == string(decrypted) {
		fmt.Println("Success: Payload matches after decrypt!")
	} else {
		fmt.Println("Failure: Payload does not match after decrypt.")
	}
}

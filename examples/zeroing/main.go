package main

import (
	"fmt"

	"github.com/sethfduke/capsule-crypto"
)

func main() {
	// Pretend this is a sensitive key
	secret := []byte("VerySensitiveKeyMaterial")

	fmt.Println("Before Zero:", secret)

	// Securely zero the byte slice
	crypto.Zero(secret)

	fmt.Println("After Zero:", secret)
}

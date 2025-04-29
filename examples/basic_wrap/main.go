package main

import (
	"crypto/rand"
	"fmt"

	"github.com/sethfduke/capsule-crypto"
)

func main() {
	password := "SuperSecurePassword!"
	config := crypto.DefaultArgonConfig

	// Generate a random 32-byte DEK
	dek := make([]byte, config.KeyLen)
	_, err := rand.Read(dek)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original DEK:", dek)

	// Wrap the DEK with a password
	wrapped, err := crypto.WrapDEKWithPassword(password, dek, config)
	if err != nil {
		panic(err)
	}

	fmt.Println("Wrapped Key (base64):", wrapped.WrappedKey)
	fmt.Println("Salt (base64):", wrapped.Salt)
	fmt.Println("Nonce (base64):", wrapped.Nonce)

	// Unwrap the DEK with the password
	unwrappedDEK, err := crypto.UnwrapDEKWithPassword(password, wrapped, config)
	if err != nil {
		panic(err)
	}

	fmt.Println("Unwrapped DEK:", unwrappedDEK)

	// Verify
	if string(dek) == string(unwrappedDEK) {
		fmt.Println("Success: DEK matches after unwrap!")
	} else {
		fmt.Println("Failure: DEK does not match after unwrap.")
	}
}

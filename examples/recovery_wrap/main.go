package main

import (
	"crypto/rand"
	"fmt"

	"github.com/sethfduke/capsule-crypto"
)

func main() {
	// Generate RSA recovery key pair
	pubPEM, privPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated Recovery Public Key (PEM):")
	fmt.Println(string(pubPEM))

	fmt.Println("Generated Recovery Private Key (PEM):")
	fmt.Println(string(privPEM))

	// Create a VaultKeyWrapper with a DEK
	dek := make([]byte, crypto.DefaultArgonConfig.KeyLen)
	_, err = rand.Read(dek)
	if err != nil {
		panic(err)
	}

	vaultObject := &crypto.VaultKeyWrapper{
		WrappedKey: crypto.ToBase64String(dek),
	}

	// Wrap the WrappedKey for recovery
	err = crypto.WrapForRecovery(vaultObject, pubPEM)
	if err != nil {
		panic(err)
	}

	fmt.Println("RecoveryWrapped (base64):", vaultObject.RecoveryWrapped)

	// Unwrap the RecoveryWrapped back
	unwrapped, err := crypto.UnwrapWithRecovery(privPEM, vaultObject)
	if err != nil {
		panic(err)
	}

	fmt.Println("Unwrapped Recovery DEK (bytes):", unwrapped)

	if string(unwrapped) == vaultObject.WrappedKey {
		fmt.Println("Success: Recovery unwrap matches original wrapped key!")
	} else {
		fmt.Println("Failure: Recovery unwrap does not match.")
	}
}

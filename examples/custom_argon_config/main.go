package main

import (
	"fmt"

	"github.com/sethfduke/capsule-crypto"
)

func main() {
	password := "MyCustomPassword"

	// Custom ArgonConfig
	customConfig := crypto.ArgonConfig{
		Memory:      128 * 1024, // 128 MiB
		Iterations:  5,
		Parallelism: 4,
		SaltLen:     16,
		KeyLen:      32,
	}

	fmt.Println("Using custom Argon2id config:")
	fmt.Printf("Memory: %d KiB, Iterations: %d, Parallelism: %d\n", customConfig.Memory, customConfig.Iterations, customConfig.Parallelism)

	// Derive key
	key, salt, err := crypto.DeriveKey(password, nil, customConfig)
	if err != nil {
		panic(err)
	}

	fmt.Println("Derived key:", key)
	fmt.Println("Used salt (base64):", crypto.ToBase64String(salt))
}

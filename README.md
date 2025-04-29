# Capsule Crypto Library

A lightweight, production-grade Go library for securely encrypting, wrapping, and recovering Data
Encryption Keys (DEKs). Designed for password-based protection, payload encryption, RSA-based recovery, and more.

---

## ✨ Features

- AES-GCM encryption with strong authenticated encryption
- HMAC verification for payload integrity
- Argon2id password-based key derivation with configurable parameters
- Base64 encoding helpers (URL-safe, no padding)
- RSA public/private key wrapping for recovery scenarios
- Vault key structure to bundle wrapped keys, salts, nonces
- Secure zeroing of sensitive material from memory

---

## 📦 Installation

```bash
go get github.com/sethfduke/capsule-crypto
```

Import into your Go project:

```go
import "github.com/sethfduke/capsule-crypto"
```

---

## 🚀 Quick Usage Example

Wrapping and unwrapping a DEK with a password:

```go
password := "SuperSecurePassword!"
config := crypto.DefaultArgonConfig

dek := make([]byte, config.KeyLen) // 32 bytes for AES-256
_, err := rand.Read(dek)
if err != nil {
	panic(err)
}

wrapped, err := crypto.WrapDEKWithPassword(password, dek, config)
if err != nil {
	panic(err)
}

unwrappedDEK, err := crypto.UnwrapDEKWithPassword(password, wrapped, config)
if err != nil {
	panic(err)
}
```

---

## 📚 Example Projects

Explore the `examples/` directory for runnable demonstrations:

| Example | Description |
|:---|:---|
| `basic_wrap/` | Wrap and unwrap a DEK using a password. |
| `payload_encryption/` | Encrypt and decrypt a payload using a DEK with AES-GCM + HMAC. |
| `recovery_wrap/` | Wrap a DEK using an RSA public key and recover it using the private key. |
| `zeroing/` | Securely zero a byte slice from memory to remove sensitive data. |
| `custom_argon_config/` | Derive keys using a custom Argon2id configuration for adjustable security. |

Each folder has a `main.go` you can run independently:

```bash
cd examples/basic_wrap
go run main.go
```

---

## 🛠 Testing

Unit tests are written using [Ginkgo v2](https://onsi.github.io/ginkgo/).

To run the tests:

```bash
ginkgo ./...
```

or using Go's native test runner:

```bash
go test ./...
```

Tests have full coverage across all major components.

---

## 🤝 Contributing

We welcome contributions!  
To contribute:

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Write tests covering your changes.
4. Submit a pull request with a clear description of your changes.

### Development Standards:
- All new code should have appropriate unit tests.
- Follow Go formatting (`go fmt`).
- Follow semantic commit messages (e.g., `feat: add recovery support`).

If you are adding new encryption primitives, ensure proper use of modern, vetted cryptographic algorithms.

---

## 📜 License

This project is licensed under the **Apache 2.0 License**.  
You are free to use, modify, and distribute it with proper attribution.

See [LICENSE](LICENSE) for full terms.
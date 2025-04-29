package crypto_test

import (
	"crypto/rand"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/sethfduke/capsule-crypto"
)

var _ = Describe("WrapDEK and UnwrapDEK", func() {
	var (
		password string
		dek      []byte
		config   ArgonConfig
	)

	BeforeEach(func() {
		password = "SuperSecurePassword123!"
		config = DefaultArgonConfig

		dek = make([]byte, config.KeyLen)
		_, err := rand.Read(dek)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("WrapDEKWithPassword and UnwrapDEKWithPassword", func() {
		It("successfully wraps and unwraps a DEK with a password", func() {
			wrapped, err := WrapDEKWithPassword(password, dek, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(wrapped).NotTo(BeNil())
			Expect(wrapped.WrappedKey).NotTo(BeEmpty())
			Expect(wrapped.Salt).NotTo(BeEmpty())
			Expect(wrapped.Nonce).NotTo(BeEmpty())

			unwrapped, err := UnwrapDEKWithPassword(password, wrapped, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(unwrapped).To(Equal(dek))
		})

		It("fails to unwrap with an incorrect password", func() {
			wrapped, err := WrapDEKWithPassword(password, dek, config)
			Expect(err).NotTo(HaveOccurred())

			_, err = UnwrapDEKWithPassword("WrongPassword!", wrapped, config)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("password incorrect or data corrupted"))
		})

		It("fails to wrap a DEK that is the wrong size", func() {
			badDEK := make([]byte, config.KeyLen-1)

			_, err := WrapDEKWithPassword(password, badDEK, config)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("DEK must be"))
		})
	})

	Describe("WrapDEK and UnwrapDEK", func() {
		It("successfully wraps and unwraps manually without VaultKeyWrapper", func() {
			saltB64, nonceB64, wrappedB64, err := WrapDEK(password, dek, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(saltB64).NotTo(BeEmpty())
			Expect(nonceB64).NotTo(BeEmpty())
			Expect(wrappedB64).NotTo(BeEmpty())

			unwrapped, err := UnwrapDEK(password, saltB64, nonceB64, wrappedB64, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(unwrapped).To(Equal(dek))
		})

		It("fails unwrapping if salt is not valid base64", func() {
			_, err := UnwrapDEK(password, "notbase64!", "good", "good", config)
			Expect(err).To(HaveOccurred())
		})

		It("fails unwrapping if nonce is not valid base64", func() {
			saltB64, _, wrappedB64, err := WrapDEK(password, dek, config)
			Expect(err).NotTo(HaveOccurred())

			_, err = UnwrapDEK(password, saltB64, "notbase64!", wrappedB64, config)
			Expect(err).To(HaveOccurred())
		})

		It("fails unwrapping if wrapped key is not valid base64", func() {
			saltB64, nonceB64, _, err := WrapDEK(password, dek, config)
			Expect(err).NotTo(HaveOccurred())

			_, err = UnwrapDEK(password, saltB64, nonceB64, "notbase64!", config)
			Expect(err).To(HaveOccurred())
		})

		It("fails unwrapping if ciphertext is tampered", func() {
			saltB64, nonceB64, wrappedB64, err := WrapDEK(password, dek, config)
			Expect(err).NotTo(HaveOccurred())

			ctBytes, err := FromBase64String(wrappedB64)
			Expect(err).NotTo(HaveOccurred())
			ctBytes[0] ^= 0xFF
			tamperedWrappedB64 := ToBase64String(ctBytes)

			_, err = UnwrapDEK(password, saltB64, nonceB64, tamperedWrappedB64, config)
			Expect(err).To(HaveOccurred())
		})
	})
})

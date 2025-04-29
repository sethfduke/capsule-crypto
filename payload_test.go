package crypto_test

import (
	"crypto/rand"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/sethfduke/capsule-crypto"
)

var _ = Describe("EncryptPayload and DecryptPayload", func() {
	var (
		dek       []byte
		plaintext []byte
	)

	BeforeEach(func() {
		dek = make([]byte, 32)
		_, err := rand.Read(dek)
		Expect(err).NotTo(HaveOccurred())

		plaintext = []byte("this is some test plaintext")
	})

	Describe("EncryptPayload", func() {
		It("successfully encrypts plaintext and returns ivB64, hmacB64, ciphertext", func() {
			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())
			Expect(ivB64).NotTo(BeEmpty())
			Expect(hmacB64).NotTo(BeEmpty())
			Expect(ciphertext).NotTo(BeEmpty())
		})
	})

	Describe("DecryptPayload", func() {
		It("successfully decrypts the ciphertext back to the original plaintext", func() {
			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())

			decrypted, err := DecryptPayload(dek, ivB64, hmacB64, ciphertext)
			Expect(err).NotTo(HaveOccurred())
			Expect(decrypted).To(Equal(plaintext))
		})

		It("fails decryption if HMAC is tampered", func() {
			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())

			// Tamper with the HMAC
			hmacBytes, err := FromBase64String(hmacB64)
			Expect(err).NotTo(HaveOccurred())
			hmacBytes[0] ^= 0xFF
			tamperedHmacB64 := ToBase64String(hmacBytes)

			_, err = DecryptPayload(dek, ivB64, tamperedHmacB64, ciphertext)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("HMAC verification failed"))
		})

		It("fails decryption if IV is tampered", func() {
			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())

			// Tamper with the IV
			ivBytes, err := FromBase64String(ivB64)
			Expect(err).NotTo(HaveOccurred())
			ivBytes[0] ^= 0xFF
			tamperedIvB64 := ToBase64String(ivBytes)

			_, err = DecryptPayload(dek, tamperedIvB64, hmacB64, ciphertext)
			Expect(err).To(HaveOccurred())
		})

		It("fails decryption if ciphertext is tampered", func() {
			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())

			ciphertext[len(ciphertext)-1] ^= 0xFF

			_, err = DecryptPayload(dek, ivB64, hmacB64, ciphertext)
			Expect(err).To(HaveOccurred())
		})

		It("fails decryption if the base64-decoded IV is invalid", func() {
			_, err := DecryptPayload(dek, "not_base64!!", "still_not_base64!!", []byte("some ciphertext"))
			Expect(err).To(HaveOccurred())
		})

		It("fails decryption if the base64-decoded HMAC is invalid", func() {
			ivB64, _, ciphertext, err := EncryptPayload(dek, plaintext)
			Expect(err).NotTo(HaveOccurred())

			_, err = DecryptPayload(dek, ivB64, "not_base64!!", ciphertext)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Round-trip behavior", func() {
		It("encodes and decodes random payloads correctly", func() {
			randomPlaintext := make([]byte, 128)
			_, err := rand.Read(randomPlaintext)
			Expect(err).NotTo(HaveOccurred())

			ivB64, hmacB64, ciphertext, err := EncryptPayload(dek, randomPlaintext)
			Expect(err).NotTo(HaveOccurred())

			decrypted, err := DecryptPayload(dek, ivB64, hmacB64, ciphertext)
			Expect(err).NotTo(HaveOccurred())
			Expect(decrypted).To(Equal(randomPlaintext))
		})
	})
})

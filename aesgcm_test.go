package crypto_test

import (
	"crypto/rand"
	. "github.com/sethfduke/capsule-crypto"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test Suite")
}

var _ = Describe("AES-GCM Encrypt/Decrypt", func() {
	var (
		key128 []byte
		key192 []byte
		key256 []byte
		plain  []byte
	)

	BeforeEach(func() {
		key128 = make([]byte, 16)
		key192 = make([]byte, 24)
		key256 = make([]byte, 32)

		_, err := rand.Read(key128)
		Expect(err).NotTo(HaveOccurred())

		_, err = rand.Read(key192)
		_, err = rand.Read(key192)
		Expect(err).NotTo(HaveOccurred())

		_, err = rand.Read(key256)
		Expect(err).NotTo(HaveOccurred())

		plain = []byte("this is some plaintext")
	})

	DescribeTable("successful encryption and decryption with valid keys",
		func(keyLen int) {
			key := make([]byte, keyLen)
			_, err := rand.Read(key)
			Expect(err).NotTo(HaveOccurred())

			nonce, ciphertext, err := AESGCMEncrypt(key, plain)
			Expect(err).NotTo(HaveOccurred())
			Expect(nonce).NotTo(BeEmpty())
			Expect(ciphertext).NotTo(BeEmpty())

			decrypted, err := AESGCMDecrypt(key, nonce, ciphertext)
			Expect(err).NotTo(HaveOccurred())
			Expect(decrypted).To(Equal(plain))
		},
		Entry("AES-128 key", 16),
		Entry("AES-192 key", 24),
		Entry("AES-256 key", 32),
	)

	It("fails encryption with invalid key size", func() {
		badKey := make([]byte, 10)
		_, _, err := AESGCMEncrypt(badKey, plain)
		Expect(err).To(HaveOccurred())
	})

	It("fails decryption with wrong key", func() {
		_, ciphertext, err := AESGCMEncrypt(key256, plain)
		Expect(err).NotTo(HaveOccurred())

		// Wrong key
		wrongKey := make([]byte, 32)
		copy(wrongKey, key256)
		wrongKey[0] ^= 0xFF

		nonce, _, _ := AESGCMEncrypt(key256, plain)
		_, err = AESGCMDecrypt(wrongKey, nonce, ciphertext)
		Expect(err).To(HaveOccurred())
	})

	It("fails decryption with wrong nonce", func() {
		nonce, ciphertext, err := AESGCMEncrypt(key256, plain)
		Expect(err).NotTo(HaveOccurred())

		// Corrupt the nonce
		nonce[0] ^= 0xFF
		_, err = AESGCMDecrypt(key256, nonce, ciphertext)
		Expect(err).To(HaveOccurred())
	})

	It("fails decryption with tampered ciphertext", func() {
		nonce, ciphertext, err := AESGCMEncrypt(key256, plain)
		Expect(err).NotTo(HaveOccurred())

		ciphertext[len(ciphertext)-1] ^= 0xFF
		_, err = AESGCMDecrypt(key256, nonce, ciphertext)
		Expect(err).To(HaveOccurred())
	})

	It("produces different ciphertext for same plaintext due to random nonce", func() {
		_, ciphertext1, err := AESGCMEncrypt(key256, plain)
		Expect(err).NotTo(HaveOccurred())

		_, ciphertext2, err := AESGCMEncrypt(key256, plain)
		Expect(err).NotTo(HaveOccurred())

		Expect(ciphertext1).NotTo(Equal(ciphertext2))
	})

	It("handles empty plaintext correctly", func() {
		nonce, ciphertext, err := AESGCMEncrypt(key256, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ciphertext).NotTo(BeEmpty())

		decrypted, err := AESGCMDecrypt(key256, nonce, ciphertext)
		Expect(err).NotTo(HaveOccurred())
		Expect(decrypted).To(BeEmpty())
	})

	It("fails encryption when AES cipher creation fails (invalid key size)", func() {
		badKey := []byte("shortkey")
		_, _, err := AESGCMEncrypt(badKey, plain)
		Expect(err).To(HaveOccurred())
	})

	It("fails decryption when AES cipher creation fails (invalid key size)", func() {
		badKey := []byte("shortkey")
		_, err := AESGCMDecrypt(badKey, key128, key128) // key128 reused as dummy input
		Expect(err).To(HaveOccurred())
	})
})

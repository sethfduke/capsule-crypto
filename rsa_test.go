package crypto_test

import (
	"crypto/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/sethfduke/capsule-crypto"
)

var _ = Describe("RSA Operations", func() {
	var (
		pubPEM  []byte
		privPEM []byte
	)

	BeforeEach(func() {
		var err error
		pubPEM, privPEM, err = GenerateRSAKeyPair()
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("GenerateRSAKeyPair", func() {
		It("generates valid PEM-encoded public and private keys", func() {
			Expect(pubPEM).NotTo(BeEmpty())
			Expect(privPEM).NotTo(BeEmpty())
		})
	})

	Describe("ParsePublicKey", func() {
		It("successfully parses a valid public key PEM", func() {
			pub, err := ParsePublicKey(pubPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(pub).NotTo(BeNil())
		})

		It("fails to parse invalid public key PEM", func() {
			_, err := ParsePublicKey([]byte("not a real pem"))
			Expect(err).To(HaveOccurred())
		})

		It("fails to parse when PEM block type is wrong", func() {
			_, err := ParsePublicKey(privPEM)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ParsePrivateKey", func() {
		It("successfully parses a valid private key PEM", func() {
			priv, err := ParsePrivateKey(privPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(priv).NotTo(BeNil())
		})

		It("fails to parse invalid private key PEM", func() {
			_, err := ParsePrivateKey([]byte("invalid pem"))
			Expect(err).To(HaveOccurred())
		})

		It("fails to parse when PEM block type is wrong", func() {
			_, err := ParsePrivateKey(pubPEM)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("RSAEncrypt and RSADecrypt", func() {
		var (
			pubKey  *rsa.PublicKey
			privKey *rsa.PrivateKey
		)

		BeforeEach(func() {
			var err error
			pubKey, err = ParsePublicKey(pubPEM)
			Expect(err).NotTo(HaveOccurred())

			privKey, err = ParsePrivateKey(privPEM)
			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully encrypts and decrypts a message", func() {
			message := []byte("this is a secret message")

			ciphertext, err := RSAEncrypt(pubKey, message)
			Expect(err).NotTo(HaveOccurred())
			Expect(ciphertext).NotTo(BeEmpty())

			plaintext, err := RSADecrypt(privKey, ciphertext)
			Expect(err).NotTo(HaveOccurred())
			Expect(plaintext).To(Equal(message))
		})

		It("fails to decrypt tampered ciphertext", func() {
			message := []byte("another secret")

			ciphertext, err := RSAEncrypt(pubKey, message)
			Expect(err).NotTo(HaveOccurred())

			ciphertext[0] ^= 0xFF

			_, err = RSADecrypt(privKey, ciphertext)
			Expect(err).To(HaveOccurred())
		})
	})
})

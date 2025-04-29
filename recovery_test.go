package crypto_test

import (
	. "github.com/sethfduke/capsule-crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("WrapForRecovery and UnwrapWithRecovery", func() {
	var (
		vaultKey    string
		vaultObject *VaultKeyWrapper
		pubPEM      []byte
		privPEM     []byte
	)

	BeforeEach(func() {
		vaultKey = "supersecretvaultkey123"

		vaultObject = &VaultKeyWrapper{
			WrappedKey: vaultKey,
		}

		var err error
		pubPEM, privPEM, err = GenerateRSAKeyPair()
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("WrapForRecovery", func() {
		It("successfully wraps the WrappedKey with a public key", func() {
			err := WrapForRecovery(vaultObject, pubPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(vaultObject.RecoveryWrapped).NotTo(BeEmpty())
		})

		It("returns an error if public key parsing fails", func() {
			err := WrapForRecovery(vaultObject, []byte("invalid pem"))
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("UnwrapWithRecovery", func() {
		BeforeEach(func() {
			err := WrapForRecovery(vaultObject, pubPEM)
			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully unwraps the RecoveryWrapped field with the private key", func() {
			unwrapped, err := UnwrapWithRecovery(privPEM, vaultObject)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(unwrapped)).To(Equal(vaultKey))
		})

		It("returns an error if private key parsing fails", func() {
			_, err := UnwrapWithRecovery([]byte("invalid pem"), vaultObject)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error if RecoveryWrapped is not valid base64", func() {
			vaultObject.RecoveryWrapped = "notbase64!!"
			_, err := UnwrapWithRecovery(privPEM, vaultObject)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error if RSA decryption fails (tampered ciphertext)", func() {
			wrappedBytes, err := FromBase64String(vaultObject.RecoveryWrapped)
			Expect(err).NotTo(HaveOccurred())
			wrappedBytes[0] ^= 0xFF
			vaultObject.RecoveryWrapped = ToBase64String(wrappedBytes)

			_, err = UnwrapWithRecovery(privPEM, vaultObject)
			Expect(err).To(HaveOccurred())
		})
	})
})

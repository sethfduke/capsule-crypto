package crypto_test

import (
	. "github.com/sethfduke/capsule-crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ToBase64String and FromBase64String", func() {
	var (
		data       []byte
		encodedStr string
	)

	BeforeEach(func() {
		data = []byte("hello world")
		encodedStr = ToBase64String(data)
	})

	Describe("ToBase64String", func() {
		It("encodes data into a base64 URL-safe string without padding", func() {
			Expect(encodedStr).NotTo(BeEmpty())
			Expect(encodedStr).NotTo(ContainSubstring("=")) // Should have no padding
		})

		It("produces consistent encoding for the same input", func() {
			secondEncoded := ToBase64String(data)
			Expect(secondEncoded).To(Equal(encodedStr))
		})
	})

	Describe("FromBase64String", func() {
		It("decodes a valid base64 string back to the original data", func() {
			decoded, err := FromBase64String(encodedStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded).To(Equal(data))
		})

		It("returns an error for invalid base64 strings", func() {
			invalidBase64 := "this_is_not_base64!"
			_, err := FromBase64String(invalidBase64)
			Expect(err).To(HaveOccurred())
		})

		It("handles empty string input", func() {
			decoded, err := FromBase64String("")
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded).To(BeEmpty())
		})
	})

	Describe("Round-trip behavior", func() {
		It("encodes and decodes correctly for random data", func() {
			original := []byte{0x01, 0x02, 0x03, 0x04, 0xFF}
			encoded := ToBase64String(original)
			decoded, err := FromBase64String(encoded)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded).To(Equal(original))
		})
	})
})

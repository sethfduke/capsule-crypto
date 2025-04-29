package crypto_test

import (
	"crypto/rand"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/sethfduke/capsule-crypto"
)

var _ = Describe("DeriveKey and Zero", func() {
	var (
		password string
		config   ArgonConfig
	)

	BeforeEach(func() {
		password = "strongpassword123"
		config = DefaultArgonConfig
	})

	Describe("DeriveKey", func() {
		It("successfully derives a key with a provided salt", func() {
			salt := make([]byte, config.SaltLen)
			_, err := rand.Read(salt)
			Expect(err).NotTo(HaveOccurred())

			key, usedSalt, err := DeriveKey(password, salt, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).To(HaveLen(int(config.KeyLen)))
			Expect(usedSalt).To(Equal(salt))
		})

		It("successfully derives a key and generates a random salt if none is provided", func() {
			key, usedSalt, err := DeriveKey(password, nil, config)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).To(HaveLen(int(config.KeyLen)))
			Expect(usedSalt).To(HaveLen(int(config.SaltLen)))
		})

		It("generates different salts and different keys when no salt is provided", func() {
			key1, salt1, err := DeriveKey(password, nil, config)
			Expect(err).NotTo(HaveOccurred())

			key2, salt2, err := DeriveKey(password, nil, config)
			Expect(err).NotTo(HaveOccurred())

			Expect(salt1).NotTo(Equal(salt2))
			Expect(key1).NotTo(Equal(key2))
		})

		It("derives the same key if using the same salt and password", func() {
			salt := make([]byte, config.SaltLen)
			_, err := rand.Read(salt)
			Expect(err).NotTo(HaveOccurred())

			key1, usedSalt1, err := DeriveKey(password, salt, config)
			Expect(err).NotTo(HaveOccurred())

			key2, usedSalt2, err := DeriveKey(password, usedSalt1, config)
			Expect(err).NotTo(HaveOccurred())

			Expect(key1).To(Equal(key2))
			Expect(usedSalt1).To(Equal(usedSalt2))
		})
	})

	Describe("Zero", func() {
		It("overwrites the byte slice with zeros", func() {
			data := []byte("sensitive data")
			Zero(data)
			Expect(data).To(Equal(make([]byte, len(data))))
		})

		It("handles an empty byte slice without panic", func() {
			var data []byte
			Expect(func() {
				Zero(data)
			}).NotTo(Panic())
			Expect(data).To(BeEmpty())
		})
	})
})

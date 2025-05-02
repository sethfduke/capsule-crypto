package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/sethfduke/capsule-crypto"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt data using a password",
	RunE: func(cmd *cobra.Command, args []string) error {
		dekB64, _ := cmd.Flags().GetString("dek")
		nonceB64, _ := cmd.Flags().GetString("nonce")
		ciphertextB64, _ := cmd.Flags().GetString("ciphertext")

		dek, err := base64.StdEncoding.DecodeString(dekB64)
		if err != nil {
			return fmt.Errorf("invalid DEK: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(nonceB64)
		if err != nil {
			return fmt.Errorf("invalid nonce: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
		if err != nil {
			return fmt.Errorf("invalid ciphertext: %w", err)
		}

		plaintext, err := crypto.AESGCMDecrypt(dek, nonce, ct)
		if err != nil {
			return err
		}

		fmt.Printf(`{"plaintext":"%s"}`+"\n", plaintext)
		return nil
	},
}

func init() {
	decryptCmd.Flags().String("dek", "", "Base64-encoded DEK to decrypt with (required)")
	decryptCmd.Flags().String("nonce", "", "Base64-encoded nonce (required)")
	decryptCmd.Flags().String("ciphertext", "", "Base64-encoded ciphertext (required)")
	decryptCmd.MarkFlagRequired("dek")
	decryptCmd.MarkFlagRequired("nonce")
	decryptCmd.MarkFlagRequired("ciphertext")
	rootCmd.AddCommand(decryptCmd)
}

package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/sethfduke/capsule-crypto"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt input using a DEK",
	RunE: func(cmd *cobra.Command, args []string) error {
		dekB64, _ := cmd.Flags().GetString("dek")
		inputPath, _ := cmd.Flags().GetString("in")
		plaintext, _ := cmd.Flags().GetString("data")

		dek, err := base64.StdEncoding.DecodeString(dekB64)
		if err != nil {
			return fmt.Errorf("invalid DEK: %w", err)
		}

		var data []byte
		switch {
		case inputPath != "":
			data, err = os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("read input file: %w", err)
			}
		case plaintext != "":
			data = []byte(plaintext)
		default:
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
		}

		nonce, ct, err := crypto.AESGCMEncrypt(dek, data)
		if err != nil {
			return err
		}

		fmt.Printf(`{"nonce":"%s","ciphertext":"%s"}`+"\n",
			base64.StdEncoding.EncodeToString(nonce),
			base64.StdEncoding.EncodeToString(ct))

		return nil
	},
}

func init() {
	encryptCmd.Flags().String("dek", "", "Base64-encoded DEK (required)")
	encryptCmd.Flags().String("data", "", "Plaintext string to encrypt (optional)")
	encryptCmd.Flags().String("in", "", "File to encrypt (optional)")
	encryptCmd.MarkFlagRequired("dek")
	rootCmd.AddCommand(encryptCmd)
}

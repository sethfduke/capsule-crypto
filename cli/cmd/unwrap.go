package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/sethfduke/capsule-crypto"
	"github.com/spf13/cobra"
)

var unwrapCmd = &cobra.Command{
	Use:   "unwrap",
	Short: "Unwrap the capsule DEK using a password",
	RunE: func(cmd *cobra.Command, args []string) error {
		password, _ := cmd.Flags().GetString("password")
		wrappedB64, _ := cmd.Flags().GetString("wrapped")
		saltB64, _ := cmd.Flags().GetString("salt")
		nonceB64, _ := cmd.Flags().GetString("nonce")

		wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
		if err != nil {
			return fmt.Errorf("invalid base64 wrapped key: %w", err)
		}
		salt, err := base64.StdEncoding.DecodeString(saltB64)
		if err != nil {
			return fmt.Errorf("invalid base64 salt: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(nonceB64)
		if err != nil {
			return fmt.Errorf("invalid base64 nonce: %w", err)
		}

		vaultKey := crypto.VaultKeyWrapper{
			WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
			Salt:       base64.StdEncoding.EncodeToString(salt),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
		}

		dek, err := crypto.UnwrapDEKWithPassword(password, &vaultKey, crypto.DefaultArgonConfig)
		if err != nil {
			return fmt.Errorf("failed to unwrap DEK: %w", err)
		}

		fmt.Printf(`{"dek":"%s"}`+"\n", base64.StdEncoding.EncodeToString(dek))
		return nil
	},
}

func init() {
	unwrapCmd.Flags().String("password", "", "Password to unwrap with (required)")
	unwrapCmd.Flags().String("wrapped", "", "Base64-encoded wrapped key (required)")
	unwrapCmd.Flags().String("salt", "", "Base64-encoded salt (required)")
	unwrapCmd.Flags().String("nonce", "", "Base64-encoded nonce (required)")
	unwrapCmd.MarkFlagRequired("password")
	unwrapCmd.MarkFlagRequired("wrapped")
	unwrapCmd.MarkFlagRequired("salt")
	unwrapCmd.MarkFlagRequired("nonce")
	rootCmd.AddCommand(unwrapCmd)
}

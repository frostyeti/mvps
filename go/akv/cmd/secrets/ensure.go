/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/spf13/cobra"
)

var (
	SecretsCmd *cobra.Command
	RootCmd    *cobra.Command
)

// ensureCmd represents the ensure command
var ensureCmd = &cobra.Command{
	Use:   "ensure",
	Short: "Ensure a secret exists in Azure Key Vault, creating it if needed",
	Long: `Get a secret from Azure Key Vault, or create it if it doesn't exist.

If the secret already exists, its value is returned.
If the secret does not exist, a new random secret is generated and stored.

Generation options control the created secret:
  --size       Size of the secret in characters (default: 16)
  --no-upper   Exclude uppercase letters
  --no-lower   Exclude lowercase letters
  --no-digits  Exclude digits
  --no-special Exclude special characters
  --special    Specify custom special characters (default: @_-{}|#!~:^)
  --chars      Use only these specific characters (overrides other character options)

Examples:
  # Ensure a secret exists (default 16-character random)
  akv ensure --key my-secret

  # Ensure with custom size
  akv ensure --key my-secret --size 32

  # Ensure with only lowercase and digits
  akv ensure --key my-secret -U -S

  # Ensure with custom characters
  akv ensure --key my-secret --chars "abc123!@#"`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		key, _ := cmd.Flags().GetString("key")

		// Validate key is provided
		if key == "" {
			cmd.PrintErrf("Error: --key must be provided\n")
			return
		}

		// Resolve the vault URI
		resolved, err := resolveUri(uri, vault)
		if err != nil {
			cmd.PrintErrf("Error resolving URI: %v\n", err)
			return
		}

		url := resolved.Uri

		// Get credentials
		cred, err := getCredential(cmd)
		if err != nil {
			cmd.PrintErrf("Error getting credentials: %v\n", err)
			return
		}

		// Create Key Vault client
		client, err := azsecrets.NewClient(url, cred, nil)
		if err != nil {
			cmd.PrintErrf("Error creating Key Vault client: %v\n", err)
			return
		}

		// Try to get the secret
		resp, err := client.GetSecret(cmd.Context(), key, "", nil)
		if err == nil && resp.Value != nil {
			// Secret exists, return its value
			fmt.Println(*resp.Value)
			return
		}

		// Secret doesn't exist, generate a new one
		secretValue, err := generateSecret(cmd)
		if err != nil {
			cmd.PrintErrf("Error generating secret: %v\n", err)
			return
		}

		// Set the secret
		params := azsecrets.SetSecretParameters{
			Value: &secretValue,
		}

		_, err = client.SetSecret(cmd.Context(), key, params, nil)
		if err != nil {
			cmd.PrintErrf("Error setting secret %s: %v\n", key, err)
			return
		}

		// Return the generated value
		fmt.Println(secretValue)
	},
}

func init() {
}

func Init(secretsCmd, rootCmd *cobra.Command) {
	SecretsCmd = secretsCmd
	RootCmd = rootCmd
	secretsCmd.AddCommand(ensureCmd)
	rootCmd.AddCommand(ensureCmd)

	ensureCmd.Flags().String("key", "", "The name of the secret to ensure (required)")
	ensureCmd.MarkFlagRequired("key")

	// Generation options (same as set command)
	ensureCmd.Flags().Int("size", 16, "Size of the generated secret in characters")
	ensureCmd.Flags().BoolP("no-upper", "U", false, "Exclude uppercase letters from generated secret")
	ensureCmd.Flags().BoolP("no-lower", "L", false, "Exclude lowercase letters from generated secret")
	ensureCmd.Flags().BoolP("no-digits", "D", false, "Exclude digits from generated secret")
	ensureCmd.Flags().BoolP("no-special", "S", false, "Exclude special characters from generated secret")
	ensureCmd.Flags().String("special", "", "Custom special characters to use (default: @_-{}|#!~:^)")
	ensureCmd.Flags().String("chars", "", "Use only these specific characters (overrides all other character options)")
}

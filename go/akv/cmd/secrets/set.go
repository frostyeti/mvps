/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/frostyeti/mvps/go/secrets"
	"github.com/spf13/cobra"
)

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Set a secret in Azure Key Vault",
	Long: `Set a single secret value in Azure Key Vault.

The value can be provided through one of five exclusive options:
  --value      Provide the value directly on the command line
  --file       Read the value from a file
  --var        Read the value from an environment variable
  --stdin      Read the value from standard input
  --generate   Generate a random secret value

When using --generate, additional options control the generated secret:
  --size       Size of the secret in characters (default: 16)
  --no-upper   Exclude uppercase letters
  --no-lower   Exclude lowercase letters
  --no-digits  Exclude digits
  --no-special Exclude special characters
  --special    Specify custom special characters (default: @_-{}|#!~:^)
  --chars      Use only these specific characters (overrides other character options)

Examples:
  # Set a secret with a value from command line
  akv set --key my-secret --value "secret-value"

  # Set a secret with a value from a file
  akv set --key my-secret --file ./secret.txt

  # Set a secret with a value from an environment variable
  akv set --key my-secret --var MY_ENV_VAR

  # Set a secret with a value from stdin
  echo "secret-value" | akv set --key my-secret --stdin

  # Generate a random 32-character secret
  akv set --key my-secret --generate --size 32

  # Generate a secret with only lowercase and digits
  akv set --key my-secret --gen -U -S

  # Generate a secret with custom characters
  akv set --key my-secret --gen --chars "abc123!@#"`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		key, _ := cmd.Flags().GetString("key")

		value, _ := cmd.Flags().GetString("value")
		file, _ := cmd.Flags().GetString("file")
		varName, _ := cmd.Flags().GetString("var")
		stdin, _ := cmd.Flags().GetBool("stdin")
		generate, _ := cmd.Flags().GetBool("generate")

		// Validate that exactly one input method is specified
		inputMethods := 0
		if value != "" {
			inputMethods++
		}
		if file != "" {
			inputMethods++
		}
		if varName != "" {
			inputMethods++
		}
		if stdin {
			inputMethods++
		}
		if generate {
			inputMethods++
		}

		if inputMethods == 0 {
			cmd.PrintErrf("Error: must specify exactly one of --value, --file, --var, --stdin, or --generate\n")
			return
		}

		if inputMethods > 1 {
			cmd.PrintErrf("Error: options --value, --file, --var, --stdin, and --generate are mutually exclusive\n")
			return
		}

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

		// Get the secret value based on the input method
		var secretValue string
		switch {
		case value != "":
			secretValue = value
		case file != "":
			data, err := os.ReadFile(file)
			if err != nil {
				cmd.PrintErrf("Error reading file %s: %v\n", file, err)
				return
			}
			secretValue = string(data)
		case varName != "":
			secretValue = os.Getenv(varName)
			if secretValue == "" {
				cmd.PrintErrf("Warning: environment variable %s is empty or not set\n", varName)
			}
		case stdin:
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				cmd.PrintErrf("Error reading from stdin: %v\n", err)
				return
			}
			secretValue = string(data)
		case generate:
			secretValue, err = generateSecret(cmd)
			if err != nil {
				cmd.PrintErrf("Error generating secret: %v\n", err)
				return
			}
		}

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

		// Set the secret
		params := azsecrets.SetSecretParameters{
			Value: &secretValue,
		}

		_, err = client.SetSecret(cmd.Context(), key, params, nil)
		if err != nil {
			cmd.PrintErrf("Error setting secret %s: %v\n", key, err)
			return
		}

		fmt.Printf("Successfully set secret: %s\n", key)
	},
}

func generateSecret(cmd *cobra.Command) (string, error) {
	size, _ := cmd.Flags().GetInt("size")
	noUpper, _ := cmd.Flags().GetBool("no-upper")
	noLower, _ := cmd.Flags().GetBool("no-lower")
	noDigits, _ := cmd.Flags().GetBool("no-digits")
	noSpecial, _ := cmd.Flags().GetBool("no-special")
	specialChars, _ := cmd.Flags().GetString("special")
	chars, _ := cmd.Flags().GetString("chars")

	builder := secrets.NewOptionsBuilder()
	builder.WithSize(int16(size))

	if chars != "" {
		// If --chars is specified, use only those characters
		builder.WithChars(chars)
	} else {
		// Otherwise, build character set from flags
		builder.WithUpper(!noUpper)
		builder.WithLower(!noLower)
		builder.WithDigits(!noDigits)

		if noSpecial {
			builder.WithNoSymbols()
		} else if specialChars != "" {
			builder.WithSymbols(specialChars)
		} else {
			// Default special characters
			builder.WithSymbols("@_-{}|#!`~:^")
		}
	}

	opts := builder.Build()
	return opts.Generate()
}

func InitSet(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(setCmd)
	rootCmd.AddCommand(setCmd)

	setCmd.Flags().String("key", "", "The name of the secret to set (required)")
	setCmd.MarkFlagRequired("key")

	setCmd.Flags().String("value", "", "The secret value (exclusive with --file, --var, --stdin, --generate)")
	setCmd.Flags().String("file", "", "Path to file containing the secret value (exclusive with --value, --var, --stdin, --generate)")
	setCmd.Flags().String("var", "", "Environment variable name containing the secret value (exclusive with --value, --file, --stdin, --generate)")
	setCmd.Flags().Bool("stdin", false, "Read the secret value from stdin (exclusive with --value, --file, --var, --generate)")
	setCmd.Flags().BoolP("generate", "g", false, "Generate a random secret value (exclusive with --value, --file, --var, --stdin)")

	// Generation options
	setCmd.Flags().Int("size", 16, "Size of the generated secret in characters")
	setCmd.Flags().BoolP("no-upper", "U", false, "Exclude uppercase letters from generated secret")
	setCmd.Flags().BoolP("no-lower", "L", false, "Exclude lowercase letters from generated secret")
	setCmd.Flags().BoolP("no-digits", "D", false, "Exclude digits from generated secret")
	setCmd.Flags().BoolP("no-special", "S", false, "Exclude special characters from generated secret")
	setCmd.Flags().String("special", "", "Custom special characters to use (default: @_-{}|#!`~:^)")
	setCmd.Flags().String("chars", "", "Use only these specific characters (overrides all other character options)")

	// Mark the flags as mutually exclusive
	setCmd.MarkFlagsMutuallyExclusive("value", "file", "var", "stdin", "generate")
}

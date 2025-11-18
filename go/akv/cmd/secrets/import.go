/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/spf13/cobra"
)

// SecretImport represents the import format for a secret (can be string or object)
type SecretImport struct {
	Value     string            `json:"value"`
	Tags      map[string]string `json:"tags,omitempty"`
	ExpiresAt *time.Time        `json:"expiresAt,omitempty"`
	NotBefore *time.Time        `json:"notBefore,omitempty"`
	Enabled   *bool             `json:"enabled,omitempty"`
}

// importCmd represents the import command
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a JSON file to Azure Key Vault",
	Long: `Import secrets from a JSON file to Azure Key Vault.

The JSON file should contain an object where each property represents a secret.
Property values can be either:
  1. A string (simple secret value)
  2. An object with the following properties:
     - value: The secret value (required)
     - tags: Key-value pairs of tags (optional)
     - expiresAt: Expiration timestamp (optional)
     - notBefore: Not-before timestamp (optional)
     - enabled: Whether the secret is enabled (optional)

Examples:
  # Import secrets from a file
  akv secrets import --file secrets.json

  # Import from stdin
  cat secrets.json | akv secrets import --stdin

Example JSON format:
  {
    "simple-secret": "simple-value",
    "complex-secret": {
      "value": "secret-value",
      "tags": {
        "environment": "production",
        "team": "backend"
      },
      "expiresAt": "2026-12-31T23:59:59Z",
      "enabled": true
    }
  }`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		file, _ := cmd.Flags().GetString("file")
		stdin, _ := cmd.Flags().GetBool("stdin")

		// Validate that exactly one input method is specified
		if file == "" && !stdin {
			cmd.PrintErrf("Error: must specify either --file or --stdin\n")
			return
		}

		if file != "" && stdin {
			cmd.PrintErrf("Error: --file and --stdin are mutually exclusive\n")
			return
		}

		// Resolve the vault URI
		resolved, err := resolveUri(uri, vault)
		if err != nil {
			cmd.PrintErrf("Error resolving URI: %v\n", err)
			return
		}

		url := resolved.Uri

		// Read JSON data
		var jsonData []byte
		if file != "" {
			jsonData, err = os.ReadFile(file)
			if err != nil {
				cmd.PrintErrf("Error reading file %s: %v\n", file, err)
				return
			}
		} else {
			jsonData, err = os.ReadFile(os.Stdin.Name())
			if err != nil {
				cmd.PrintErrf("Error reading from stdin: %v\n", err)
				return
			}
		}

		// Parse JSON - first try as raw map to handle both string and object values
		var rawData map[string]json.RawMessage
		err = json.Unmarshal(jsonData, &rawData)
		if err != nil {
			cmd.PrintErrf("Error parsing JSON: %v\n", err)
			return
		}

		// Convert to SecretImport objects
		secrets := make(map[string]SecretImport)
		for key, rawValue := range rawData {
			var simpleValue string
			// Try to unmarshal as string first
			if err := json.Unmarshal(rawValue, &simpleValue); err == nil {
				secrets[key] = SecretImport{
					Value: simpleValue,
				}
			} else {
				// Try to unmarshal as SecretImport object
				var secretObj SecretImport
				if err := json.Unmarshal(rawValue, &secretObj); err != nil {
					cmd.PrintErrf("Error parsing secret %s: %v\n", key, err)
					return
				}
				secrets[key] = secretObj
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

		// Import each secret
		successCount := 0
		failCount := 0

		for name, secretImport := range secrets {
			// Build secret parameters
			params := azsecrets.SetSecretParameters{
				Value: &secretImport.Value,
			}

			// Set attributes if provided
			if secretImport.ExpiresAt != nil || secretImport.NotBefore != nil || secretImport.Enabled != nil {
				params.SecretAttributes = &azsecrets.SecretAttributes{
					Expires:   secretImport.ExpiresAt,
					NotBefore: secretImport.NotBefore,
					Enabled:   secretImport.Enabled,
				}
			}

			// Set tags if provided
			if len(secretImport.Tags) > 0 {
				params.Tags = make(map[string]*string)
				for k, v := range secretImport.Tags {
					tagValue := v
					params.Tags[k] = &tagValue
				}
			}

			// Set the secret
			_, err = client.SetSecret(cmd.Context(), name, params, nil)
			if err != nil {
				cmd.PrintErrf("Error setting secret %s: %v\n", name, err)
				failCount++
				continue
			}

			successCount++
			fmt.Printf("Imported secret: %s\n", name)
		}

		// Print summary
		if failCount > 0 {
			fmt.Printf("\nImported %d of %d secret(s) (%d failed)\n", successCount, len(secrets), failCount)
		} else {
			fmt.Printf("\nSuccessfully imported %d secret(s)\n", successCount)
		}
	},
}

func InitImport(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(importCmd)

	importCmd.Flags().StringP("file", "f", "", "Input JSON file path")
	importCmd.Flags().Bool("stdin", false, "Read JSON from stdin")
}

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

// SecretExport represents the export format for a secret
type SecretExport struct {
	Value     string            `json:"value"`
	Tags      map[string]string `json:"tags,omitempty"`
	ExpiresAt *time.Time        `json:"expiresAt,omitempty"`
	NotBefore *time.Time        `json:"notBefore,omitempty"`
	Enabled   *bool             `json:"enabled,omitempty"`
}

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets from Azure Key Vault to a JSON file",
	Long: `Export all secrets from Azure Key Vault to a JSON file.

The exported JSON file contains an object where each property represents a secret.
Each secret value is an object containing:
  - value: The secret value
  - tags: Key-value pairs of tags (optional)
  - expiresAt: Expiration timestamp (optional)
  - notBefore: Not-before timestamp (optional)
  - enabled: Whether the secret is enabled (optional)

Examples:
  # Export all secrets to a file
  akv secrets export --file secrets.json

  # Export to stdout
  akv secrets export

  # Export with pretty formatting
  akv secrets export --file secrets.json --pretty`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		file, _ := cmd.Flags().GetString("file")
		pretty, _ := cmd.Flags().GetBool("pretty")

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

		// Export all secrets
		exported := make(map[string]SecretExport)

		pager := client.NewListSecretPropertiesPager(nil)
		for pager.More() {
			page, err := pager.NextPage(cmd.Context())
			if err != nil {
				cmd.PrintErrf("Error listing secrets: %v\n", err)
				return
			}

			for _, secretProps := range page.Value {
				if secretProps.ID == nil {
					continue
				}

				name := secretProps.ID.Name()
				if name == "" {
					continue
				}

				// Get the full secret with its value
				resp, err := client.GetSecret(cmd.Context(), name, "", nil)
				if err != nil {
					cmd.PrintErrf("Error getting secret %s: %v\n", name, err)
					continue
				}

				export := SecretExport{}

				if resp.Value != nil {
					export.Value = *resp.Value
				}

				if resp.Attributes != nil {
					export.ExpiresAt = resp.Attributes.Expires
					export.NotBefore = resp.Attributes.NotBefore
					export.Enabled = resp.Attributes.Enabled
				}

				if len(resp.Tags) > 0 {
					export.Tags = make(map[string]string)
					for k, v := range resp.Tags {
						if v != nil {
							export.Tags[k] = *v
						}
					}
				}

				exported[name] = export
			}
		}

		// Marshal to JSON
		var jsonData []byte
		if pretty {
			jsonData, err = json.MarshalIndent(exported, "", "  ")
		} else {
			jsonData, err = json.Marshal(exported)
		}

		if err != nil {
			cmd.PrintErrf("Error marshaling secrets to JSON: %v\n", err)
			return
		}

		// Write to file or stdout
		if file != "" {
			err = os.WriteFile(file, jsonData, 0600)
			if err != nil {
				cmd.PrintErrf("Error writing to file %s: %v\n", file, err)
				return
			}
			fmt.Fprintf(os.Stderr, "Exported %d secret(s) to %s\n", len(exported), file)
		} else {
			fmt.Println(string(jsonData))
		}
	},
}

func InitExport(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(exportCmd)

	exportCmd.Flags().StringP("file", "f", "", "Output file path (default: stdout)")
	exportCmd.Flags().BoolP("pretty", "p", false, "Pretty-print JSON output")
}

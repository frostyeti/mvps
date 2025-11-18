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

// SecretSync represents the sync format for a secret
type SecretSync struct {
	Value     *string            `json:"value,omitempty"`
	Tags      map[string]*string `json:"tags,omitempty"`
	ExpiresAt *time.Time         `json:"expiresAt,omitempty"`
	NotBefore *time.Time         `json:"notBefore,omitempty"`
	Enabled   *bool              `json:"enabled,omitempty"`
	Delete    *bool              `json:"delete,omitempty"`
	Purge     *bool              `json:"purge,omitempty"`
}

// syncCmd represents the sync command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync secrets to Azure Key Vault, updating only when values differ",
	Long: `Sync secrets to Azure Key Vault from a JSON file.

This command intelligently updates secrets only when their values differ from
what's currently stored in the vault. Property values can be either:
  1. A string (simple secret value - updates only if different)
  2. An object with the following properties:
     - value: The secret value (updates if different)
     - tags: Key-value pairs of tags (updates if different)
     - expiresAt: Expiration timestamp (updates if different)
     - notBefore: Not-before timestamp (updates if different)
     - enabled: Whether the secret is enabled (updates if different)
     - delete: If true, delete the secret (ignores other properties)
     - purge: If true with delete, purge the secret after deletion

Omitted/null properties are not updated in the vault.

Examples:
  # Sync secrets from a file
  akv secrets sync --file secrets.json

  # Sync from stdin
  cat secrets.json | akv secrets sync --stdin

  # Dry run to see what would change
  akv secrets sync --file secrets.json --dry-run

Example JSON format:
  {
    "simple-secret": "new-value",
    "complex-secret": {
      "value": "secret-value",
      "tags": {
        "environment": "production"
      },
      "enabled": true
    },
    "secret-to-delete": {
      "delete": true,
      "purge": true
    }
  }`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		file, _ := cmd.Flags().GetString("file")
		stdin, _ := cmd.Flags().GetBool("stdin")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

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

		// Convert to SecretSync objects
		secrets := make(map[string]SecretSync)
		for key, rawValue := range rawData {
			var simpleValue string
			// Try to unmarshal as string first
			if err := json.Unmarshal(rawValue, &simpleValue); err == nil {
				secrets[key] = SecretSync{
					Value: &simpleValue,
				}
			} else {
				// Try to unmarshal as SecretSync object
				var secretObj SecretSync
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

		// Sync each secret
		createdCount := 0
		updatedCount := 0
		deletedCount := 0
		skippedCount := 0
		failCount := 0

		for name, secretSync := range secrets {
			// Handle deletion
			if secretSync.Delete != nil && *secretSync.Delete {
				if dryRun {
					fmt.Printf("[DRY RUN] Would delete secret: %s", name)
					if secretSync.Purge != nil && *secretSync.Purge {
						fmt.Printf(" (with purge)")
					}
					fmt.Println()
					deletedCount++
					continue
				}

				_, err := client.DeleteSecret(cmd.Context(), name, nil)
				if err != nil {
					cmd.PrintErrf("Error deleting secret %s: %v\n", name, err)
					failCount++
					continue
				}

				fmt.Printf("Deleted secret: %s\n", name)
				deletedCount++

				// Purge if requested
				if secretSync.Purge != nil && *secretSync.Purge {
					_, err = client.PurgeDeletedSecret(cmd.Context(), name, nil)
					if err != nil {
						cmd.PrintErrf("Error purging secret %s: %v\n", name, err)
					} else {
						fmt.Printf("Purged secret: %s\n", name)
					}
				}
				continue
			}

			// Get existing secret
			existing, err := client.GetSecret(cmd.Context(), name, "", nil)
			secretExists := err == nil

			// Determine if we need to update
			needsUpdate := false
			isNew := !secretExists

			if isNew {
				needsUpdate = true
			} else {
				// Check if value differs
				if secretSync.Value != nil && existing.Value != nil {
					if *secretSync.Value != *existing.Value {
						needsUpdate = true
					}
				}

				// Check if tags differ
				if secretSync.Tags != nil {
					if !tagsEqual(secretSync.Tags, existing.Tags) {
						needsUpdate = true
					}
				}

				// Check if attributes differ
				if existing.Attributes != nil {
					if secretSync.ExpiresAt != nil {
						if !timeEqual(secretSync.ExpiresAt, existing.Attributes.Expires) {
							needsUpdate = true
						}
					}
					if secretSync.NotBefore != nil {
						if !timeEqual(secretSync.NotBefore, existing.Attributes.NotBefore) {
							needsUpdate = true
						}
					}
					if secretSync.Enabled != nil {
						if existing.Attributes.Enabled == nil || *secretSync.Enabled != *existing.Attributes.Enabled {
							needsUpdate = true
						}
					}
				}
			}

			if !needsUpdate {
				skippedCount++
				continue
			}

			if dryRun {
				if isNew {
					fmt.Printf("[DRY RUN] Would create secret: %s\n", name)
				} else {
					fmt.Printf("[DRY RUN] Would update secret: %s\n", name)
				}
				if isNew {
					createdCount++
				} else {
					updatedCount++
				}
				continue
			}

			// Build the value - use provided value or keep existing
			var valueToSet string
			if secretSync.Value != nil {
				valueToSet = *secretSync.Value
			} else if existing.Value != nil {
				valueToSet = *existing.Value
			}

			// Build secret parameters
			params := azsecrets.SetSecretParameters{
				Value: &valueToSet,
			}

			// Merge attributes
			if secretSync.ExpiresAt != nil || secretSync.NotBefore != nil || secretSync.Enabled != nil {
				params.SecretAttributes = &azsecrets.SecretAttributes{}

				// Use new values if provided, otherwise keep existing
				if secretSync.ExpiresAt != nil {
					params.SecretAttributes.Expires = secretSync.ExpiresAt
				} else if existing.Attributes != nil {
					params.SecretAttributes.Expires = existing.Attributes.Expires
				}

				if secretSync.NotBefore != nil {
					params.SecretAttributes.NotBefore = secretSync.NotBefore
				} else if existing.Attributes != nil {
					params.SecretAttributes.NotBefore = existing.Attributes.NotBefore
				}

				if secretSync.Enabled != nil {
					params.SecretAttributes.Enabled = secretSync.Enabled
				} else if existing.Attributes != nil {
					params.SecretAttributes.Enabled = existing.Attributes.Enabled
				}
			} else if existing.Attributes != nil {
				// Keep all existing attributes if none specified
				params.SecretAttributes = existing.Attributes
			}

			// Merge tags
			if secretSync.Tags != nil {
				params.Tags = secretSync.Tags
			} else if existing.Tags != nil {
				params.Tags = existing.Tags
			}

			// Set the secret
			_, err = client.SetSecret(cmd.Context(), name, params, nil)
			if err != nil {
				cmd.PrintErrf("Error setting secret %s: %v\n", name, err)
				failCount++
				continue
			}

			if isNew {
				fmt.Printf("Created secret: %s\n", name)
				createdCount++
			} else {
				fmt.Printf("Updated secret: %s\n", name)
				updatedCount++
			}
		}

		// Print summary
		fmt.Println()
		if dryRun {
			fmt.Println("[DRY RUN] Summary:")
		}
		fmt.Printf("Created: %d\n", createdCount)
		fmt.Printf("Updated: %d\n", updatedCount)
		fmt.Printf("Deleted: %d\n", deletedCount)
		fmt.Printf("Skipped (no changes): %d\n", skippedCount)
		if failCount > 0 {
			fmt.Printf("Failed: %d\n", failCount)
		}
	},
}

// Helper function to compare tags
func tagsEqual(a map[string]*string, b map[string]*string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if (v == nil) != (bv == nil) {
			return false
		}
		if v != nil && bv != nil && *v != *bv {
			return false
		}
	}
	return true
}

// Helper function to compare times
func timeEqual(a *time.Time, b *time.Time) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return a.Equal(*b)
}

func InitSync(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(syncCmd)

	syncCmd.Flags().StringP("file", "f", "", "Input JSON file path")
	syncCmd.Flags().Bool("stdin", false, "Read JSON from stdin")
	syncCmd.Flags().Bool("dry-run", false, "Show what would be changed without making changes")
}

/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/gobwas/glob"
	"github.com/spf13/cobra"
)

// lsCmd represents the ls command
var lsCmd = &cobra.Command{
	Use:     "ls [filter]",
	Aliases: []string{"list"},
	Short:   "List secrets in Azure Key Vault",
	Long: `List all secrets in Azure Key Vault.

Optionally provide a glob pattern to filter the results. The pattern supports
standard glob syntax including wildcards (* and ?).

Examples:
  # List all secrets
  akv ls -v vault-name



  # List secrets matching a pattern
  akv ls -v vault-name "app-*"

  # List secrets with wildcards
  akv ls -v vault-name "*-prod"
  akv ls -v vault-name "db-*-password"
  # List secrets using the alias
  akv list -v vault-name "api-key-*"`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")

		var filterPattern string
		if len(args) > 0 {
			filterPattern = args[0]
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

		// Compile glob pattern if provided
		var matcher glob.Glob
		if filterPattern != "" {
			matcher, err = glob.Compile(filterPattern)
			if err != nil {
				cmd.PrintErrf("Error compiling glob pattern: %v\n", err)
				return
			}
		}

		// List secrets
		pager := client.NewListSecretPropertiesPager(nil)
		count := 0
		matchCount := 0

		for pager.More() {
			page, err := pager.NextPage(cmd.Context())
			if err != nil {
				cmd.PrintErrf("Error listing secrets: %v\n", err)
				return
			}

			for _, secret := range page.Value {
				if secret.ID == nil {
					continue
				}

				// Extract the secret name from the ID
				// ID format: https://{vault-name}.vault.azure.net/secrets/{secret-name}
				name := ""
				if secret.ID.Name() != "" {
					name = secret.ID.Name()
				}

				if name == "" {
					continue
				}

				count++

				// Apply filter if specified
				if matcher != nil {
					if !matcher.Match(name) {
						continue
					}
				}

				matchCount++
				fmt.Println(name)
			}
		}

		// Print summary to stderr so it doesn't interfere with piping
		if filterPattern != "" {
			fmt.Fprintf(os.Stderr, "\nShowing %d of %d secrets (filtered by: %s)\n", matchCount, count, filterPattern)
		} else {
			fmt.Fprintf(os.Stderr, "\nTotal secrets: %d\n", count)
		}
	},
}

func InitLs(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(lsCmd)
	rootCmd.AddCommand(lsCmd)
}

/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/spf13/cobra"
)

// rmCmd represents the rm command
var rmCmd = &cobra.Command{
	Use:     "rm <key>...",
	Aliases: []string{"remove"},
	Short:   "Remove one or more secrets from Azure Key Vault",
	Long: `Remove (delete) one or more secrets from Azure Key Vault.

By default, deleted secrets can be recovered. Use --purge to permanently delete them.
You will be prompted to confirm deletion unless --yes is specified.

Examples:
  # Remove a single secret (with confirmation)
  akv rm --key my-secret

  # Remove multiple secrets
  akv rm --key secret1 --key secret2 --key secret3

  # Remove and purge a secret without confirmation
  akv rm --key my-secret --purge --yes

  # Remove secrets with short flags
  akv rm -k secret1 -k secret2 -y`,

	Run: func(cmd *cobra.Command, args []string) {
		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		keys, _ := cmd.Flags().GetStringSlice("key")
		purge, _ := cmd.Flags().GetBool("purge")
		yes, _ := cmd.Flags().GetBool("yes")

		if len(args) > 0 {
			keys = append(keys, args...)
		}

		// Validate that at least one key is provided
		if len(keys) == 0 {
			cmd.PrintErrf("Error: at least one --key or <key> must be provided\n")
			return
		}

		// Resolve the vault URI
		resolved, err := resolveUri(uri, vault)
		if err != nil {
			cmd.PrintErrf("Error resolving URI: %v\n", err)
			return
		}

		url := resolved.Uri

		// Prompt for confirmation unless --yes is specified
		if !yes {
			fmt.Printf("You are about to delete %d secret(s)", len(keys))
			if purge {
				fmt.Printf(" (with purge)")
			}
			fmt.Println(":")
			for _, key := range keys {
				fmt.Printf("  - %s\n", key)
			}
			fmt.Print("\nDo you want to continue? [y/N]: ")

			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				cmd.PrintErrf("Error reading confirmation: %v\n", err)
				return
			}

			response = strings.ToLower(strings.TrimSpace(response))
			if response != "y" && response != "yes" {
				fmt.Println("Operation cancelled")
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

		// Delete each secret
		deletedCount := 0
		for _, key := range keys {
			// Delete the secret
			_, err := client.DeleteSecret(cmd.Context(), key, nil)
			if err != nil {
				cmd.PrintErrf("Error deleting secret %s: %v\n", key, err)
				continue
			}

			deletedCount++
			fmt.Printf("Deleted secret: %s\n", key)

			// Purge if requested
			if purge {
				_, err = client.PurgeDeletedSecret(cmd.Context(), key, nil)
				if err != nil {
					cmd.PrintErrf("Error purging secret %s: %v\n", key, err)
					continue
				}
				fmt.Printf("Purged secret: %s\n", key)
			}
		}

		if deletedCount == len(keys) {
			fmt.Printf("\nSuccessfully processed %d secret(s)\n", deletedCount)
		} else {
			fmt.Printf("\nProcessed %d out of %d secret(s)\n", deletedCount, len(keys))
		}
	},
}

func InitRm(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(rmCmd)

	rmCmd.Flags().StringSliceP("key", "k", []string{}, "Name of secret(s) to remove (can be specified multiple times)")

	rmCmd.Flags().Bool("purge", false, "Permanently purge the secret after deletion (cannot be recovered)")
	rmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
}

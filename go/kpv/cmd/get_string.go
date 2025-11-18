/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getStringCmd represents the get-string command
var getStringCmd = &cobra.Command{
	Use:   "get-string",
	Short: "Get a custom string field from a KeePass entry",
	Long: `Get a custom string field from a KeePass entry.

This command retrieves non-standard string fields from entries. Standard fields
like Title, Username, Password, URL, and Notes should be retrieved using the
regular 'get' command.

Custom string fields can be either protected (encrypted) or unprotected.

Examples:
  # Get a custom string field
  kpv get-string --key my-secret --field api-key

  # Get from a specific vault
  kpv get-string --vault myvault --key my-secret --field custom-field`,

	Run: func(cmd *cobra.Command, args []string) {
		key, _ := cmd.Flags().GetString("key")
		field, _ := cmd.Flags().GetString("field")

		if key == "" {
			cmd.PrintErrf("Error: --key must be provided\n")
			return
		}

		if field == "" {
			cmd.PrintErrf("Error: --field must be provided\n")
			return
		}

		// Standard fields that should not be retrieved with get-string
		standardFields := map[string]bool{
			"Title":    true,
			"Username": true,
			"Password": true,
			"URL":      true,
			"Notes":    true,
		}

		if standardFields[field] {
			cmd.PrintErrf("Error: '%s' is a standard field. Use the 'get' command instead.\n", field)
			return
		}

		kdbx, _, err := openKeePass(cmd)
		if err != nil {
			cmd.PrintErrf("Error opening KeePass vault: %v\n", err)
			return
		}

		entry := kdbx.FindEntry(key)
		if entry == nil {
			cmd.PrintErrf("Error: secret %s not found\n", key)
			return
		}

		value := entry.GetContent(field)
		if value == "" {
			cmd.PrintErrf("Error: field '%s' not found in secret %s\n", field, key)
			return
		}

		fmt.Println(value)
	},
}

func init() {
	rootCmd.AddCommand(getStringCmd)

	getStringCmd.Flags().StringP("key", "k", "", "The secret name/key (required)")
	getStringCmd.Flags().StringP("field", "f", "", "The custom field name to retrieve (required)")
}

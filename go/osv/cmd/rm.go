/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// rmCmd represents the rm command
var rmCmd = &cobra.Command{
	Use:     "rm",
	Aliases: []string{"remove"},
	Short:   "Remove one or more secrets from the keyring",
	Long: `Remove (delete) one or more secrets from the OS keyring.

You will be prompted to confirm deletion unless --yes is specified.

Examples:
  # Remove a single secret (with confirmation)
  osv rm --key my-secret

  # Remove multiple secrets
  osv rm --key secret1 --key secret2 --key secret3

  # Remove secrets without confirmation
  osv rm --key my-secret --yes

  # Remove secrets with short flags
  osv rm -k secret1 -k secret2 -y`,

	Run: func(cmd *cobra.Command, args []string) {
		keys, _ := cmd.Flags().GetStringSlice("key")
		yes, _ := cmd.Flags().GetBool("yes")

		// Validate that at least one key is provided
		if len(keys) == 0 {
			cmd.PrintErrf("Error: at least one --key must be provided\n")
			return
		}

		kr, err := openKeyring(cmd)
		if err != nil {
			cmd.PrintErrf("Error opening keyring: %v\n", err)
			return
		}

		// Prompt for confirmation unless --yes is specified
		if !yes {
			fmt.Printf("You are about to delete %d secret(s):\n", len(keys))
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

		// Delete each secret
		deletedCount := 0
		for _, key := range keys {
			err := kr.Remove(key)
			if err != nil {
				cmd.PrintErrf("Error deleting secret %s: %v\n", key, err)
				continue
			}

			deletedCount++
			fmt.Printf("Deleted secret: %s\n", key)
		}

		if deletedCount == len(keys) {
			fmt.Printf("\nSuccessfully deleted %d secret(s)\n", deletedCount)
		} else {
			fmt.Printf("\nDeleted %d out of %d secret(s)\n", deletedCount, len(keys))
		}
	},
}

func init() {
	rootCmd.AddCommand(rmCmd)

	rmCmd.Flags().StringSliceP("key", "k", []string{}, "Name of secret(s) to remove (can be specified multiple times)")
	rmCmd.MarkFlagRequired("key")

	rmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
}

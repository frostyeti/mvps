/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/gobwas/glob"
	"github.com/spf13/cobra"
)

// lsCmd represents the ls command
var lsCmd = &cobra.Command{
	Use:     "ls [filter]",
	Aliases: []string{"list"},
	Short:   "List secrets in the keyring",
	Long: `List all secrets in the OS keyring.

Optionally provide a glob pattern to filter the results. The pattern supports
standard glob syntax including wildcards (* and ?).

Examples:
  # List all secrets
  osv ls

  # List secrets matching a pattern
  osv ls "app-*"

  # List secrets with wildcards
  osv ls "*-prod"
  osv ls "db-*-password"

  # List secrets using the alias
  osv list "api-key-*"`,

	Run: func(cmd *cobra.Command, args []string) {
		var filterPattern string
		if len(args) > 0 {
			filterPattern = args[0]
		}

		kr, err := openKeyring(cmd)
		if err != nil {
			cmd.PrintErrf("Error opening keyring: %v\n", err)
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
		keys, err := kr.Keys()
		if err != nil {
			cmd.PrintErrf("Error listing secrets: %v\n", err)
			return
		}
		matchCount := 0

		for _, key := range keys {
			// Apply filter if specified
			if matcher != nil {
				if !matcher.Match(key) {
					continue
				}
			}

			matchCount++
			fmt.Println(key)
		}

		if matchCount == 0 {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	},
}

func init() {
	rootCmd.AddCommand(lsCmd)
}

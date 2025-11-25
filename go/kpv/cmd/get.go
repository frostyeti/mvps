/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/spf13/cobra"
)

// toScreamingSnakeCase converts a string to SCREAMING_SNAKE_CASE
func toScreamingSnakeCase(input string) string {
	output := ""
	for i, char := range input {
		if char >= 'A' && char <= 'Z' {
			if i > 0 {
				output += "_"
			}
			output += string(char)
		} else if char >= 'a' && char <= 'z' {
			if i > 0 && input[i-1] >= 'A' && input[i-1] <= 'Z' {
				output += "_"
			}
			output += string(char - ('a' - 'A'))
		} else if char >= '0' && char <= '9' {
			output += string(char)
		} else {
			if i > 0 && input[i-1] != '_' {
				output += "_"
			}
		}
	}
	return output
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <key>...",
	Short: "Get one or more secrets from KeePass vault",
	Long: `Get one or more secrets from a KeePass vault.

Examples:
  # Get a single secret
  kpv get --key my-secret

  # Get multiple secrets
  kpv get --key secret1 --key secret2

  # Get secrets with different output formats
  kpv get --key secret1 --format json
  kpv get --key secret1 --format sh
  kpv get --key secret1 --format dotenv

  # Use a specific vault
  kpv get --vault myvault --key secret1
  kpv get --vault /path/to/vault.kdbx --key secret1`,

	Run: func(cmd *cobra.Command, args []string) {
		keys, _ := cmd.Flags().GetStringSlice("key")
		format, _ := cmd.Flags().GetString("format")

		if len(args) > 0 {
			keys = append(keys, args...)
		}

		if format == "" {
			format = "text"
		}

		if len(keys) == 0 {
			cmd.PrintErrf("Error: at least one --key must be provided\n")
			return
		}

		kdbx, _, err := openKeePass(cmd)
		if err != nil {
			cmd.PrintErrf("Error opening KeePass vault: %v\n", err)
			return
		}

		values := map[string]string{}
		for _, key := range keys {
			entry := kdbx.FindEntry(key)
			if entry == nil {
				cmd.PrintErrf("Error: secret %s not found\n", key)
				return
			}
			values[key] = entry.GetPassword()
		}

		switch format {
		case "json":
			b, err := json.MarshalIndent(values, "", "  ")
			if err != nil {
				cmd.PrintErrf("Error marshaling secrets to JSON: %v\n", err)
				return
			}
			fmt.Println(string(b))

		case "null-terminated":
			for _, v := range values {
				fmt.Printf("%s\x00", v)
			}

		case "sh", "bash", "zsh":
			for k, v := range values {
				fmt.Printf("export %s='%s'\n", toScreamingSnakeCase(k), v)
			}

		case "powershell", "pwsh":
			for k, v := range values {
				fmt.Printf("$Env:%s = '%s'\n", toScreamingSnakeCase(k), v)
			}

		case "dotenv", "env", ".env":
			doc := dotenv.NewDocument()
			for k, v := range values {
				doc.Set(toScreamingSnakeCase(k), v)
			}
			fmt.Println(doc.String())

		default:
			for _, v := range values {
				fmt.Println(v)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.Flags().StringSliceP("key", "k", []string{}, "Name of secret(s) to get (can be specified multiple times)")
	getCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sh, bash, zsh, powershell, pwsh, dotenv)")
}

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

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get one or more secrets from the keyring",
	Long: `Get one or more secrets from the OS keyring.

Examples:
  # Get a single secret
  osv --service <service-name> get --key my-secret

  # or set the service name via environment variable 
  export OSV_SERVICE=<service-name>
  osv get --key my-secret

  # Get multiple secrets
  osv get --key secret1 --key secret2

  # Get secrets with different output formats
  osv get --key secret1 --format json
  osv get --key secret1 --format sh
  osv get --key secret1 --format dotenv`,

	Run: func(cmd *cobra.Command, args []string) {
		keys, _ := cmd.Flags().GetStringSlice("key")
		format, _ := cmd.Flags().GetString("format")

		if format == "" {
			format = "text"
		}

		if len(keys) == 0 {
			cmd.PrintErrf("Error: at least one --key must be provided\n")
			return
		}

		kr, err := openKeyring(cmd)
		if err != nil {
			cmd.PrintErrf("Error opening keyring: %v\n", err)
			return
		}

		values := map[string]string{}
		for _, key := range keys {
			item, err := kr.Get(key)
			if err != nil {
				cmd.PrintErrf("Error getting secret %s: %v\n", key, err)
				return
			}
			values[key] = string(item.Data)
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
				fmt.Printf("export %s='%s'\n", k, v)
			}

		case "powershell", "pwsh":
			for k, v := range values {
				fmt.Printf("$Env:%s = '%s'\n", k, v)
			}

		case "dotenv", "env", ".env":
			doc := dotenv.NewDocument()
			for k, v := range values {
				doc.Set(k, v)
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
	getCmd.MarkFlagRequired("key")

	getCmd.Flags().StringP("format", "f", "text", "Output format (text, json, sh, bash, zsh, powershell, pwsh, dotenv)")
}

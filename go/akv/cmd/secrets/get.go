/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package secrets

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <key>...",
	Short: "Get one or more secrets from Azure Key Vault",
	Long: `Get one or more secrets from Azure Key Vault.

By default, secrets are output in plain text, one per line.
Use the --format flag to specify other output formats.

Examples:
  # Get a single secret
  akv get --key my-secret

  # Get multiple secrets
  akv get --key secret1 --key secret2

  # Get secrets with positional arguments
  akv get secret1 secret2

  # Get secrets in JSON format
  akv get --key my-secret --format json

  # Get secrets as environment variables for bash
  akv get --key my-secret --format bash`,
	Run: func(cmd *cobra.Command, args []string) {

		uri, _ := cmd.Flags().GetString("url")
		vault, _ := cmd.Flags().GetString("vault")
		secrets, _ := cmd.Flags().GetStringSlice("key")

		if len(args) > 0 {
			secrets = append(secrets, args...)
		}

		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = "text"
		}

		resolved, err := resolveUri(uri, vault)
		if err != nil {
			cmd.PrintErrf("Error resolving URI: %v\n", err)
			return
		}

		url := resolved.Uri
		path := resolved.Path

		if path != "" && len(secrets) == 0 {
			secrets = append(secrets, path)
		}

		if len(secrets) == 0 {
			cmd.PrintErrf("Error: at least one --key must be provided.\n")
			return
		}

		cred, err := getCredential(cmd)
		if err != nil {
			cmd.PrintErrf("Error getting credentials: %v\n", err)
			return
		}

		client, err := azsecrets.NewClient(url, cred, nil)
		if err != nil {
			cmd.PrintErrf("Error creating Key Vault client: %v\n", err)
			return
		}

		values := map[string]string{}
		for _, key := range secrets {
			resp, err := client.GetSecret(cmd.Context(), key, "", nil)
			if err != nil {
				cmd.PrintErrf("Error getting secret %s: %v\n", key, err)
				return
			}
			values[key] = *resp.Value
		}

		switch format {
		case "json":
			json.Marshal(values)
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
				n := toScreamingSnakeCase(k)
				fmt.Printf("export %s='%s'\n", n, v)
			}

		case "powershell", "pwsh":
			for k, v := range values {
				n := toScreamingSnakeCase(k)
				fmt.Printf("$Env:%s = '%s'\n", n, v)
			}

		case "github":
			envFile := os.Getenv("GITHUB_ENV")
			if envFile == "" {
				cmd.PrintErrf("GITHUB_ENV environment variable is not set\n")
				return
			}
			f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				cmd.PrintErrf("Error opening GITHUB_ENV file: %v\n", err)
				return
			}
			defer f.Close()

			for k, v := range values {
				n := toScreamingSnakeCase(k)
				_, err := f.WriteString(fmt.Sprintf("%s=%s\n", n, v))
				fmt.Println("::add-mask::" + v)
				if err != nil {
					cmd.PrintErrf("Error writing to GITHUB_ENV file: %v\n", err)
					return
				}
			}

		case "azure-pipelines", "azure-devops", "azdo", "azure":
			for k, v := range values {
				n := toScreamingSnakeCase(k)
				fmt.Printf("##vso[task.setvariable variable=%s;issecret=true;]%s\n", n, v)
			}

		case "dotenv", "env", ".env":
			doc := dotenv.NewDocument()
			for k, v := range values {
				n := toScreamingSnakeCase(k)
				doc.Set(n, v)
			}
			fmt.Println(doc.String())
		default:
			for _, v := range values {
				fmt.Println(v)
			}

			return
		}

		// Use the client to get secrets here

	},
}

func InitGet(secretsCmd, rootCmd *cobra.Command) {
	secretsCmd.AddCommand(getCmd)
	rootCmd.AddCommand(getCmd)

	flags := getCmd.Flags()
	flags.StringSliceP("key", "k", []string{}, "Name of secret(s) to get (can be specified multiple times)")
	flags.StringP("format", "f", "text", "Output format: text, json, sh, bash, zsh, powershell, pwsh, dotenv, env, .env, github, azure-pipelines")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

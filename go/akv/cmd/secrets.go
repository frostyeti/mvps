/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/frostyeti/mvps/go/akv/cmd/secrets"
	"github.com/spf13/cobra"
)

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{"secret"},
	Short:   "Manage secrets in Azure Key Vault",
	Long: `Manage secrets in Azure Key Vault.

This command provides subcommands for getting, setting, listing, removing,
and ensuring secrets exist in Azure Key Vault.`,
}

func init() {
	rootCmd.AddCommand(secretsCmd)

	// Initialize all secret subcommands
	secrets.Init(secretsCmd, rootCmd)
	secrets.InitGet(secretsCmd, rootCmd)
	secrets.InitLs(secretsCmd, rootCmd)
	secrets.InitRm(secretsCmd, rootCmd)
	secrets.InitSet(secretsCmd, rootCmd)
	secrets.InitExport(secretsCmd, rootCmd)
	secrets.InitImport(secretsCmd, rootCmd)
	secrets.InitSync(secretsCmd, rootCmd)
}

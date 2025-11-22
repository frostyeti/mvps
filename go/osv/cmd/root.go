/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "osv",
	Version: Version,
	Short:   "operating system vault",
	Long: `osv is a tool for managing secrets with Windows, macOS, and Linux OS keyrings.
	
On Windows, it uses the Credential Manager.
On macOS, it uses the Keychain.
On Linux, it uses the Secret Service API (via D-Bus).`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.osv.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	flags := rootCmd.PersistentFlags()

	service := os.Getenv("OSV_SERVICE")
	if service == "" {
		service = "login"
	}

	flags.StringP("vault", "v", service, "The keyring vault. An alias for --service")
	flags.StringP("service", "s", service, "The keyring service name")
}

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
	Use:   "akv",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
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

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.akv.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	flags := rootCmd.PersistentFlags()

	akvAuth := os.Getenv("AKV_AUTH")
	akvIdentity := os.Getenv("AKV_IDENTITY") == "true"
	akvSp := os.Getenv("AKV_SERVICE_PRINCIPAL") == "true"
	akvCli := os.Getenv("AKV_USE_CLI") == "true"
	akvDeviceCode := os.Getenv("AKV_USE_DEVICE_CODE") == "true"

	vault := os.Getenv("AKV_VAULT_NAME")
	flags.String("vault", vault, "The azure key vault name")

	uri := os.Getenv("AKV_VAULT_URI")
	flags.String("url", uri, "The azure key vault URL")

	switch akvAuth {
	case "identity":
		akvIdentity = true
	case "service-principal":
		akvSp = true
	case "use-cli":
		akvCli = true
	case "use-device-code":
		akvDeviceCode = true
	}

	flags.Bool("identity", akvIdentity, "Use Managed Identity for authentication")
	flags.Bool("service-principal", akvSp, "Use Service Principal for authentication")
	flags.Bool("use-cli", akvCli, "Use Azure CLI for authentication")
	flags.Bool("use-device-code", akvDeviceCode, "Use Device Code for authentication")

	tenantId := os.Getenv("AKV_TENANT_ID")
	clientId := os.Getenv("AKV_CLIENT_ID")
	clientSecret := os.Getenv("AKV_CLIENT_SECRET")

	flags.String("tenant-id", tenantId, "The Azure Tenant ID to use for authentication")
	flags.String("client-id", clientId, "The Azure Client ID to use for authentication")
	flags.String("client-secret", clientSecret, "The Azure Client Secret to use for authentication")

}

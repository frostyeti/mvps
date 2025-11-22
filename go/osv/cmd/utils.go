/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/99designs/keyring"
	"github.com/spf13/cobra"
)

func openKeyring(cmd *cobra.Command) (keyring.Keyring, error) {
	service, _ := cmd.Flags().GetString("service")

	if service == "login" {
		vault, _ := cmd.Flags().GetString("vault")
		if vault != service {
			service = vault
		}
	}

	kr, err := keyring.Open(keyring.Config{
		ServiceName:             service,
		LibSecretCollectionName: service,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
	})
	return kr, err
}

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

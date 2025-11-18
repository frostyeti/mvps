/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"
)

func openKeyring(cmd *cobra.Command) (keyring.Keyring, error) {
	service, _ := cmd.Flags().GetString("service")

	if service == "" {
		return nil, errors.New("service name is required")
	}

	kr, err := keyring.Open(keyring.Config{
		ServiceName: service,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
	})
	return kr, err
}

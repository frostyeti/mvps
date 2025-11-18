/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/99designs/keyring"
	"github.com/frostyeti/mvps/go/keepass"
	"github.com/frostyeti/mvps/go/secrets"
	"github.com/spf13/cobra"
)

type resolvedPath struct {
	Path string
}

func resolveVaultPath(uri string, vault string) (resolvedPath, error) {
	if uri == "" && vault == "" {
		// Default to ~/.local/share/kpv/default.kdbx on Linux/Mac
		// or %LOCALAPPDATA%/kpv/default.kdbx on Windows
		defaultPath := getDefaultVaultPath("default.kdbx")
		if _, err := os.Stat(defaultPath); err == nil {
			return resolvedPath{Path: defaultPath}, nil
		}
		return resolvedPath{}, errors.New("either --uri or --vault must be provided, or default vault must exist")
	}

	if uri != "" {
		// Parse file URI
		if strings.HasPrefix(uri, "file://") {
			parsed, err := url.Parse(uri)
			if err != nil {
				return resolvedPath{}, err
			}
			return resolvedPath{Path: parsed.Path}, nil
		}
		// Treat as file path
		absPath, err := filepath.Abs(uri)
		if err != nil {
			return resolvedPath{}, err
		}
		return resolvedPath{Path: absPath}, nil
	}

	// vault is provided
	// Check if it's an absolute path
	if filepath.IsAbs(vault) {
		return resolvedPath{Path: vault}, nil
	}

	// Check if it's a relative path or exists in current directory
	if strings.Contains(vault, string(filepath.Separator)) || strings.Contains(vault, "/") {
		absPath, err := filepath.Abs(vault)
		if err != nil {
			return resolvedPath{}, err
		}
		return resolvedPath{Path: absPath}, nil
	}

	// Check current directory
	currentDirPath := vault
	if !strings.HasSuffix(vault, ".kdbx") {
		currentDirPath = vault + ".kdbx"
	}
	if _, err := os.Stat(currentDirPath); err == nil {
		absPath, err := filepath.Abs(currentDirPath)
		if err != nil {
			return resolvedPath{}, err
		}
		return resolvedPath{Path: absPath}, nil
	}

	// Check in ~/.local/share/kpv or %LOCALAPPDATA%/kpv
	vaultName := vault
	if !strings.HasSuffix(vaultName, ".kdbx") {
		vaultName = vaultName + ".kdbx"
	}
	defaultPath := getDefaultVaultPath(vaultName)
	return resolvedPath{Path: defaultPath}, nil
}

func getDefaultVaultPath(filename string) string {
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		}
		return filepath.Join(localAppData, "kpv", filename)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".local", "share", "kpv", filename)
}

func getPassword(cmd *cobra.Command, vaultPath string) (*string, error) {
	// First check command line flag
	password, _ := cmd.Flags().GetString("password")
	if password != "" {
		return &password, nil
	}

	// Then check password file flag
	passwordFile, _ := cmd.Flags().GetString("password-file")
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, err
		}
		pwd := strings.TrimSpace(string(data))
		return &pwd, nil
	}

	// Try to get from OS keyring
	kr, err := openKeyring()
	if err == nil {
		item, err := kr.Get(vaultPath)
		if err == nil {
			pwd := string(item.Data)
			return &pwd, nil
		}
	}

	// Finally, check for .key file in default location
	// Use vault base name for key file
	baseName := filepath.Base(vaultPath)
	keyFileName := baseName[:len(baseName)-len(filepath.Ext(baseName))] + ".key"
	keyFilePath := filepath.Join(getDefaultVaultPath(""), keyFileName)

	if data, err := os.ReadFile(keyFilePath); err == nil {
		pwd := strings.TrimSpace(string(data))
		if pwd != "" {
			return &pwd, nil
		}
	}

	return nil, errors.New("password not provided via --password flag, --password-file flag, KPV_PASSWORD/KPV_PASSWORD_FILE environment variables, OS keyring, or .key file")
}

func openKeyring() (keyring.Keyring, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName: "kpv",
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
	})
	return kr, err
}

func openKeePass(cmd *cobra.Command) (*keepass.Kdbx, string, error) {
	uri, _ := cmd.Flags().GetString("url")
	vault, _ := cmd.Flags().GetString("vault")

	resolved, err := resolveVaultPath(uri, vault)
	if err != nil {
		return nil, "", err
	}

	vaultPath := resolved.Path

	password, err := getPassword(cmd, vaultPath)
	if err != nil {
		return nil, "", err
	}

	options := keepass.KdbxOptions{
		Path:      vaultPath,
		Secret:    password,
		Create:    true,
		CreateDir: true,
	}

	kdbx, err := keepass.Open(options)
	if err != nil {
		return nil, "", err
	}

	return kdbx, vaultPath, nil
}

// generateSecretWithOptions generates a secret using the provided options
// This function is shared across import and sync commands
func generateSecretWithOptions(size int, noUpper, noLower, noDigits, noSpecial bool, special, chars string) (string, error) {
	builder := secrets.NewOptionsBuilder()
	builder.WithSize(int16(size))
	builder.WithRetries(100)

	if chars != "" {
		// If chars is specified, use only those characters
		builder.WithChars(chars)
	} else {
		// Otherwise, build character set from flags
		builder.WithUpper(!noUpper)
		builder.WithLower(!noLower)
		builder.WithDigits(!noDigits)

		if noSpecial {
			builder.WithNoSymbols()
		} else if special != "" {
			builder.WithSymbols(special)
		} else {
			// Default special characters
			builder.WithSymbols("@_-{}|#!`~:^")
		}
	}

	opts := builder.Build()
	return opts.Generate()
}

package config

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

func GetRegistry() (*viper.Viper, error) {

	homeConfig, err := GetHomeConfig()
	if err != nil {
		return nil, err
	}

	v1 := viper.New()
	v1.SetConfigName("registry")
	v1.SetConfigType("json")
	v1.AddConfigPath(homeConfig)

	err = v1.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			return v1, nil
		}
		return nil, err
	}

	return v1, nil
}

func GetHomeConfig() (string, error) {
	homeConfig := os.Getenv("XSOPS_CONFIG_HOME")
	if homeConfig != "" {
		return homeConfig, nil
	}

	if homeConfig == "" {
		homeConfig = os.Getenv("XDG_CONFIG_HOME")
		if homeConfig != "" {
			return filepath.Join(homeConfig, "xsops"), nil
		}
	}

	switch runtime.GOOS {
	case "windows":
		homeConfig = os.Getenv("APPDATA")
		if homeConfig != "" {
			return filepath.Join(homeConfig, "xsops"), nil
		}

		home := os.Getenv("USERPROFILE")
		if home != "" {
			return filepath.Join(home, "AppData", "Roaming", "xsops"), nil
		}
		return "", os.ErrNotExist
	case "darwin":
		homeConfig = os.Getenv("HOME")
		if homeConfig != "" {
			return filepath.Join(homeConfig, "Library", "Application Support", "xsops"), nil
		}
		return "", os.ErrNotExist
	default:
		homeConfig = os.Getenv("HOME")
		if homeConfig != "" {
			return filepath.Join(homeConfig, ".config", "xsops"), nil
		}
		return "", os.ErrNotExist
	}
}

func GetConfig() (*viper.Viper, error) {
	homeConfig, err := GetHomeConfig()
	if err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("toml")
	v.AddConfigPath(homeConfig)

	err = v.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			return v, nil
		}
		return nil, err
	}

	return v, nil
}

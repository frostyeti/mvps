package cmd

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/frostyeti/mvps/go/sopsv/internal/config"
)

type SecretRecord struct {
	Secret    string             `json:"secret"`
	ExpiresAt *time.Time         `json:"expires_at,omitempty"`
	Tags      map[string]*string `json:"tags,omitempty"`
	Enabled   bool               `json:"enabled"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

func getUserHomeData() (string, error) {

	homeData := os.Getenv("XSOPS_DATA_HOME")
	if homeData != "" {
		return homeData, nil
	}

	homeData = os.Getenv("XDG_DATA_HOME")
	if homeData != "" {
		return filepath.Join(homeData, "xsops"), nil
	}

	switch runtime.GOOS {
	case "windows":
		homeData = os.Getenv("APPDATA")
		if homeData != "" {
			return filepath.Join(homeData, "xsops", "data"), nil
		}

		home := os.Getenv("USERPROFILE")
		if home != "" {
			return filepath.Join(home, "AppData", "Roaming", "xsops", "data"), nil
		}
		return "", os.ErrNotExist
	case "darwin":
		homeData = os.Getenv("HOME")
		if homeData != "" {
			return filepath.Join(homeData, "Library", "Application Support", "xsops", "data"), nil
		}
		return "", os.ErrNotExist
	default:
		homeData = os.Getenv("HOME")
		if homeData != "" {
			return filepath.Join(homeData, ".local", "share", "xsops"), nil
		}
		return "", os.ErrNotExist
	}
}

func getFilePath(uriString string) (string, error) {
	if uriString == "default" || uriString == "" {
		dir, err := getUserHomeData()
		if err != nil {
			return "", err
		}

		return filepath.Join(dir, "xsops.secrets.json"), nil
	}

	if uriString == "." {
		dir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "xsops.secrets.json"), nil
	}

	db, err := config.GetRegistry()
	if err != nil {
		return "", err
	}

	filePath := db.GetString(uriString)
	if filePath != "" {
		return filePath, nil
	}

	uri, err := url.Parse(uriString)
	if err == nil {
		if (uri.Scheme == "file" || uri.Scheme == "xsops") && uri.Path != "" {
			filePath = uri.Path
		}
	}

	if filePath == "" {
		filePath = uriString
		if !filepath.IsAbs(filePath) {
			filePath, err = filepath.Abs(filePath)
			if err != nil {
				return "", err
			}
		}
	}

	return filePath, nil
}

package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func UserConfigDir() (string, error) {
	configDir := os.Getenv("RUN_CONFIG_HOME")
	if configDir != "" {
		return configDir, nil
	}

	configDir = os.Getenv("RUN_CONFIG_HOME")
	if configDir != "" {
		return filepath.Join(configDir, "run"), nil
	}

	configDir, err := os.UserConfigDir()
	if err == nil {
		return filepath.Join(configDir, "run"), nil
	}

	return "", errors.New("Could not determine user config directory: " + err.Error())
}

func UserDataDir() (string, error) {
	dataDir := os.Getenv("RUN_DATA_HOME")
	if dataDir != "" {
		return dataDir, nil
	}

	dataDir = os.Getenv("XDG_DATA_HOME")
	if dataDir != "" {
		return filepath.Join(dataDir, "run"), nil
	}

	if runtime.GOOS == "windows" {
		dataDir = os.Getenv("LOCALAPPDATA")
		if dataDir != "" {
			return filepath.Join(dataDir, "run", "data"), nil
		}
	} else {
		dataDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(dataDir, ".local", "share", "run"), nil
		}
	}
	return "", errors.New("could not determine user data directory")
}

func UserCacheDir() (string, error) {
	cacheDir := os.Getenv("RUN_CACHE_HOME")
	if cacheDir != "" {
		return cacheDir, nil
	}

	cacheDir = os.Getenv("XDG_CACHE_HOME")
	if cacheDir != "" {
		return filepath.Join(cacheDir, "run"), nil
	}

	if runtime.GOOS == "windows" {
		cacheDir = os.Getenv("LOCALAPPDATA")
		if cacheDir != "" {
			return filepath.Join(cacheDir, "Cache", "run"), nil
		}

		return "", errors.New("could not determine user cache directory")
	}

	cacheDir, err := os.UserCacheDir()
	if err == nil {
		return filepath.Join(cacheDir, "run"), nil
	}

	return "", errors.New("Could not determine user cache directory: " + err.Error())
}

func UserStateDir() (string, error) {
	stateDir := os.Getenv("RUN_STATE_HOME")
	if stateDir != "" {
		return stateDir, nil
	}

	stateDir = os.Getenv("XDG_STATE_HOME")
	if stateDir != "" {
		return filepath.Join(stateDir, "run"), nil
	}

	if runtime.GOOS == "windows" {
		stateDir = os.Getenv("LOCALAPPDATA")
		if stateDir != "" {
			return filepath.Join(stateDir, "State", "run"), nil
		}
	} else {
		stateDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(stateDir, ".local", "state", "run"), nil
		}
	}
	return "", errors.New("could not determine user state directory")
}

package workflows

import "os"

func isDir(path string) bool {
	if fi, err := os.Stat(path); err == nil {
		return fi.IsDir()
	}
	return false
}

func isFile(path string) bool {
	if fi, err := os.Stat(path); err == nil {
		return !fi.IsDir()
	}
	return false
}

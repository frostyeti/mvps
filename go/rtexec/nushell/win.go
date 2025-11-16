//go:build windows

package nushell

import (
	"github.com/frostyeti/mvps/go/exec"
)

func init() {
	exec.Register("nu", &exec.Executable{
		Name:     "nu",
		Variable: "WIN_NUSHELL_EXE",
		Windows: []string{
			"C:\\Program Files\\nu\\bin\\nu.exe",
		},
	})
}

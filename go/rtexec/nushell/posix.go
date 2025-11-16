//go:build !windows

package nushell

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("nu", &exec.Executable{
		Name:     "nu",
		Variable: "NUSHELL_EXE",
		Linux: []string{
			"/bin/nu",
			"/usr/bin/nu",
		},
	})
}

//go:build !windows

package bash

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("bash", &exec.Executable{
		Name:     "bash",
		Variable: "BASH_EXE",
		Linux: []string{
			"/bin/bash",
			"/usr/bin/bash",
		},
	})
}

func resolveScriptFile(script string) string {
	return script
}

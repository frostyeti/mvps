//go:build !windows

package pwsh

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("pwsh", &exec.Executable{
		Name:     "pwsh",
		Variable: "PWSH_EXE",
		Linux: []string{
			"/bin/pwsh",
			"/usr/bin/pwsh",
		},
	})
}

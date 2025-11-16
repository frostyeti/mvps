//go:build !windows

package powershell

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("powershell", &exec.Executable{
		Name:     "powershell",
		Variable: "POWERSHELL_EXE",
		Linux: []string{
			"/bin/powershell",
			"/usr/bin/powershell",
		},
	})
}

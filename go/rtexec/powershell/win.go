//go:build windows

package powershell

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("powershell", &exec.Executable{
		Name:     "powershell",
		Variable: "WIN_POWERSHELL_EXE",
		Windows: []string{
			"${SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		},
	})
}

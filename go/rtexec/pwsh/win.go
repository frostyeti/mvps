//go:build windows

package pwsh

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("pwsh", &exec.Executable{
		Name:     "pwsh",
		Variable: "WIN_PWSH_EXE",
		Windows: []string{
			"${ProgramFiles}\\PowerShell\\7\\pwsh.exe",
			"%ProgramFiles(x86)%\\PowerShell\\7\\pwsh.exe",
			"${SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		},
	})
}

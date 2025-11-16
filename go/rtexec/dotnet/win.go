//go:build windows

package dotnet

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("dotnet", &exec.Executable{
		Name:     "dotnet",
		Variable: "WIN_DOTNET_EXE",
		Windows: []string{
			"${HOME}\\.dotnet\\dotnet.exe",
			"${LOCALAPPDATA}\\dotnet\\dotnet.exe",
			"${ProgramFiles}\\dotnet\\dotnet.exe",
			"%ProgramFiles(x86)%\\dotnet\\dotnet.exe",
		},
	})
}

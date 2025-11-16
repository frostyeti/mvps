//go:build windows

package golang

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("go", &exec.Executable{
		Name:     "go",
		Variable: "WIN_GO_EXE",
		Windows: []string{
			"${ProgramFiles}\\Go\\bin\\go.exe",
			"${ChocolateyInstall}\\lib\\go\\tools\\go\\bin\\go.exe",
		},
	})
}

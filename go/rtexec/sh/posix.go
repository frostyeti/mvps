//go:build !windows

package sh

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("sh", &exec.Executable{
		Name:     "sh",
		Variable: "SH_EXE",
		Linux: []string{
			"/bin/sh",
			"/usr/bin/sh",
		},
	})
}

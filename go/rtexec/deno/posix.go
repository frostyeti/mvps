//go:build !windows

package deno

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("deno", &exec.Executable{
		Name:     "deno",
		Variable: "DENO_EXE",
		Linux: []string{
			"/usr/bin/deno",
			"/usr/local/bin/deno",
		},
	})
}

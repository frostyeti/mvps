//go:build !windows

package node

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("node", &exec.Executable{
		Name:     "node",
		Variable: "NODE_EXE",
		Linux: []string{
			"/usr/bin/node",
			"/usr/local/bin/node",
		},
	})
}

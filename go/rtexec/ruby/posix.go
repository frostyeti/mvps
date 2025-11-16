//go:build !windows

package ruby

import "github.com/frostyeti/mvps/go/exec"

func init() {
	exec.Register("ruby", &exec.Executable{
		Name:     "ruby",
		Variable: "RUBY_EXE",
		Linux: []string{
			"/usr/bin/ruby",
			"/usr/local/bin/ruby",
		},
	})
}

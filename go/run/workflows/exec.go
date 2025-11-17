package workflows

import (
	"errors"
	"os"
	"strings"

	"github.com/frostyeti/mvps/go/exec"
)

func (ws *Workflow) Exec(args []string) error {
	if ws == nil {
		return errors.New("workflow is nil")
	}

	dir, ok := ws.Env.Get("RUN_DIR")
	if !ok || len(dir) == 0 {
		return errors.New("RUN_DIR is not set")
	}

	os.Stdout.WriteString(strings.Join(args, " ") + "\n")
	cmd := exec.NewContext(ws.Context, args[0], args[1:]...)
	cmd.Dir = dir

	cmd.WithEnvMap(ws.Env.ToMap())
	o, err := cmd.Run()
	if err != nil || o.Code != 0 {
		if o.Code != 0 {
			os.Exit(o.Code)
		} else {
			os.Exit(1)
		}
	}

	os.Exit(o.Code)
	return nil
}

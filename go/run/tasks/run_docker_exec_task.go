package tasks

import (
	"strconv"

	"github.com/frostyeti/mvps/go/cmdargs"
	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/errors"
	"github.com/frostyeti/mvps/go/exec"
)

/*

name:
  uses: docker://image-name
  run: |
    ls -la

*/

func runDocker(ctx TaskContext) *TaskResult {

	res := NewTaskResult()

	volume := ctx.Task.Cwd + ":/cwd"

	dockerArgs := []string{"run", "-i", "-t", "-w", "/cwd", "-v", volume}
	image, ok := ctx.Task.With.TryGetString("image")
	if !ok || image == "" {
		return res.Fail(errors.New("Docker exec task requires an image"))
	}

	dockerArgs = append(dockerArgs, image)
	entrypoint, ok := ctx.Task.With.TryGetString("entrypoint")
	if ok && entrypoint != "" {
		dockerArgs = append(dockerArgs, "--entrypoint", entrypoint)
	}

	runArgs := ctx.Task.Run

	withArgs, ok := ctx.Task.With.TryGetValue("args")
	args := []string{}
	if ok {
		if arr, ok := withArgs.([]interface{}); ok {
			for _, item := range arr {
				if str, ok := item.(string); ok {
					args = append(args, str)
				}
			}
		} else if str, ok := withArgs.(string); ok {
			runArgs = str
		}
	}

	if len(runArgs) > 0 {
		cmdArgs, err := cmdargs.SplitAndExpand(runArgs, func(s string) (string, error) {
			expandOptions := env.ExpandOptions{
				Get: ctx.Task.Env.GetString,
				Set: func(key, value string) error {
					ctx.Task.Env.Set(key, value)
					return nil
				},
				Keys:                ctx.Task.Env.Keys(),
				CommandSubstitution: true,
			}
			expanded, err := env.ExpandWithOptions(s, &expandOptions)
			if err != nil {
				return s, nil
			}
			return expanded, nil
		})

		if err != nil {
			return res.Fail(errors.New("Failed to parse args: " + err.Error()))
		}

		args = cmdArgs.ToArray()
	}

	if len(args) > 0 {
		dockerArgs = append(dockerArgs, args...)
	}

	cmd := exec.NewContext(ctx.Context, "docker", dockerArgs...)
	cmd.WithEnvMap(ctx.Task.Env.ToMap())

	output, err := cmd.Run()
	if err != nil {
		return res.Fail(errors.New("Failed to run docker exec: " + err.Error()))
	}

	if output.Code != 0 {
		return res.Fail(errors.New("Docker exec failed with exit code " + strconv.Itoa(output.Code)))
	}

	return res.Ok()
}

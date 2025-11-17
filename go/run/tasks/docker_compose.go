package tasks

import (
	"path/filepath"
	"strconv"

	"github.com/frostyeti/mvps/go/errors"
	"github.com/frostyeti/mvps/go/exec"
)

/*
name:
  uses: docker compose up
  with:
	file: docker-compose.yml
	swarm: true
	stack: mystack

name2:
  uses: compose up
  with:
	files:
	  - docker-compose.yml
	  - docker-compose.prod.yml
	profile: prod
	project-name: myproject
*/

func runComposeUp(ctx TaskContext) *TaskResult {
	res := NewTaskResult()
	files := []string{}
	file, ok := ctx.Task.With.TryGetString("file")
	if ok {
		files = append(files, file)
	}

	withFiles, ok := ctx.Task.With.TryGetStringSlice("files")
	if ok {
		files = append(files, withFiles...)
	}

	dockerContext, _ := ctx.Task.With.TryGetString("context")

	swarm, ok := ctx.Task.With.TryGetBool("swarm")
	if ok && swarm {
		stackName, ok := ctx.Task.With.TryGetString("stack")
		if !ok {
			p := files[len(files)-1]
			parent := filepath.Dir(p)
			if parent == "." {
				parent := filepath.Base(filepath.Dir(p))
				stackName = parent
			} else {
				stackName = parent
			}
		}

		deployArgs := []string{}

		if dockerContext != "" {
			deployArgs = append(deployArgs, "--context", dockerContext)
		}

		deployArgs = append(deployArgs, "stack", "deploy", "-d")
		for _, f := range files {
			deployArgs = append(deployArgs, "-c", f)
		}
		deployArgs = append(deployArgs, stackName)
		cmd0 := exec.NewContext(ctx.Context, "docker", deployArgs...)
		cmd0.WithEnvMap(ctx.Task.Env.ToMap())
		cmd0.WithCwd(ctx.Task.Cwd)

		out, err := cmd0.Output()
		if err != nil {
			return res.Fail(err)
		}

		if out.Code != 0 {
			return res.Fail(errors.New("Docker compose up failed with exit code " + strconv.Itoa(out.Code)))
		}

		return res.Ok()
	}

	upArgs := []string{}
	if dockerContext != "" {
		upArgs = append(upArgs, "--context", dockerContext)
	}

	upArgs = append(upArgs, "compose")
	for _, f := range files {
		upArgs = append(upArgs, "-f", f)
	}

	profile, ok := ctx.Task.With.TryGetValue("profile")
	if ok {
		if str, ok := profile.(string); ok && str != "" {
			upArgs = append(upArgs, "--profile", str)
		}

		if arr, ok := profile.([]interface{}); ok {
			for _, item := range arr {
				if str, ok := item.(string); ok && str != "" {
					upArgs = append(upArgs, "--profile", str)
				}
			}
		}
	}

	projectName, ok := ctx.Task.With.TryGetString("project-name")
	if ok && projectName != "" {
		upArgs = append(upArgs, "--project-name", projectName)
	}

	upArgs = append(upArgs, "up", "-d")

	cmd0 := exec.NewContext(ctx.Context, "docker", upArgs...)
	cmd0.WithEnvMap(ctx.Task.Env.ToMap())
	cmd0.WithCwd(ctx.Task.Cwd)

	out, err := cmd0.Output()
	if err != nil {
		return res.Fail(err)
	}

	if out.Code != 0 {
		return res.Fail(errors.New("Docker compose up failed with exit code " + strconv.Itoa(out.Code)))
	}

	return res.Ok()
}

func runComposeDown(ctx TaskContext) *TaskResult {
	res := NewTaskResult()

	files := []string{}
	file, ok := ctx.Task.With.TryGetString("file")
	if ok {
		files = append(files, file)
	}

	withFiles, ok := ctx.Task.With.TryGetStringSlice("files")
	if ok {
		files = append(files, withFiles...)
	}

	dockerContext, _ := ctx.Task.With.TryGetString("context")

	downArgs := []string{}
	if dockerContext != "" {
		downArgs = append(downArgs, "--context", dockerContext)
	}

	swarm, ok := ctx.Task.With.TryGetBool("swarm")
	if ok && swarm {
		stackName, ok := ctx.Task.With.TryGetString("stack")
		if !ok {
			p := files[len(files)-1]
			parent := filepath.Dir(p)
			if parent == "." {
				parent := filepath.Base(filepath.Dir(p))
				stackName = parent
			} else {
				stackName = parent
			}
		}

		deployArgs := []string{}

		if dockerContext != "" {
			deployArgs = append(deployArgs, "--context", dockerContext)
		}

		deployArgs = append(deployArgs, "stack", "rm", stackName)
		cmd0 := exec.NewContext(ctx.Context, "docker", deployArgs...)
		cmd0.WithEnvMap(ctx.Task.Env.ToMap())
		cmd0.WithCwd(ctx.Task.Cwd)

		out, err := cmd0.Output()
		if err != nil {
			return res.Fail(err)
		}

		if out.Code != 0 {
			return res.Fail(errors.New("Docker compose down failed with exit code " + strconv.Itoa(out.Code)))
		}

		return res.Ok()
	}

	downArgs = append(downArgs, "compose")
	for _, f := range files {
		downArgs = append(downArgs, "-f", f)
	}

	projectName, ok := ctx.Task.With.TryGetString("project-name")
	if ok && projectName != "" {
		downArgs = append(downArgs, "--project-name", projectName)
	}

	downArgs = append(downArgs, "down")

	cmd0 := exec.NewContext(ctx.Context, "docker", downArgs...)
	cmd0.WithEnvMap(ctx.Task.Env.ToMap())
	cmd0.WithCwd(ctx.Task.Cwd)

	out, err := cmd0.Output()
	if err != nil {
		return res.Fail(err)
	}

	if out.Code != 0 {
		return res.Fail(errors.New("Docker compose down failed with exit code " + strconv.Itoa(out.Code)))
	}

	return res.Ok()
}

package tasks

import (
	"net/url"
	"strings"

	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/errors"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/frostyeti/mvps/go/run/schema"
)

type taskEnvLike struct {
	Env *schema.Environment
}

func (t *taskEnvLike) Get(key string) string {
	if t.Env == nil {
		return ""
	}
	return t.Env.GetString(key)
}

func (t *taskEnvLike) Expand(s string) (string, error) {
	if t.Env == nil {
		return s, nil
	}
	opts := env.ExpandOptions{
		Get: t.Env.GetString,
		Set: func(key, value string) error {
			t.Env.Set(key, value)
			return nil
		},
		Keys:                t.Env.Keys(),
		CommandSubstitution: true,
	}

	return env.ExpandWithOptions(s, &opts)
}

func (t *taskEnvLike) Set(key, value string) {
	if t.Env == nil {
		return
	}
	t.Env.Set(key, value)
}

func (t *taskEnvLike) SplitPath() []string {
	if t.Env == nil {
		return []string{}
	}
	return t.Env.SplitPath()
}

func Run(ctx TaskContext) *TaskResult {

	// Set custom env like for exec package
	// so that the task env is used for finding executables
	oldEnv := exec.GetEnvLike()
	defer exec.SetEnvLike(oldEnv)
	envLike := &taskEnvLike{Env: &ctx.Task.Env}
	exec.SetEnvLike(envLike)

	uses := ctx.Task.Uses
	if strings.Contains(uses, "://") {
		uri, err := url.Parse(uses)

		if err != nil {
			res := NewTaskResult()
			return res.Fail(errors.New("Invalid template URI: " + err.Error()))
		}

		uses = uri.Scheme
	}

	var handler = GlobalTaskHandlers[strings.ToLower(uses)]
	if handler != nil {
		return handler(ctx)
	}

	res := NewTaskResult()
	return res.Fail(errors.New("Unsupported task type: " + uses))
}

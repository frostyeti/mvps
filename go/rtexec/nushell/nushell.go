package nushell

import (
	"context"
	"strings"

	"github.com/frostyeti/mvps/go/exec"
)

const (
	NAME = "nu"
)

var ScriptArgs = []string{}

func New(args ...string) *exec.Cmd {
	exe, _ := exec.Find(NAME, nil)
	if exe == "" {
		exe = "nu"
	}

	return exec.New(exe, args...)
}

func NewContext(ctx context.Context, args ...string) *exec.Cmd {
	exe, _ := exec.Find(NAME, nil)
	if exe == "" {
		exe = "nu"
	}

	return exec.NewContext(ctx, exe, args...)
}

func Script(script string, args ...string) *exec.Cmd {
	if !strings.ContainsAny(script, "\r\n") {
		trimmed := strings.TrimSpace(script)
		if strings.HasSuffix(trimmed, ".nu") {
			return File(trimmed, args...)
		}
	}

	return Inline(script, args...)
}

func ScriptContext(ctx context.Context, script string, args ...string) *exec.Cmd {
	if !strings.ContainsAny(script, "\r\n") {
		trimmed := strings.TrimSpace(script)
		if strings.HasSuffix(trimmed, ".nu") {
			return FileContext(ctx, trimmed, args...)
		}
	}

	return InlineContext(ctx, script, args...)
}

func File(path string, args ...string) *exec.Cmd {
	splat := append(ScriptArgs, path)
	splat = append(splat, args...)
	return New(splat...)
}

func FileContext(ctx context.Context, path string, args ...string) *exec.Cmd {
	splat := append(ScriptArgs, path)
	splat = append(splat, args...)
	return NewContext(ctx, splat...)
}

func Inline(script string, args ...string) *exec.Cmd {
	splat := append(ScriptArgs, "-c", script)
	splat = append(splat, args...)
	return New(splat...)
}

func InlineContext(ctx context.Context, script string, args ...string) *exec.Cmd {
	splat := append(ScriptArgs, "-c", script)
	splat = append(splat, args...)
	return NewContext(ctx, splat...)
}

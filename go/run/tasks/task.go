package tasks

import (
	"context"
	"time"

	"github.com/frostyeti/mvps/go/run/schema"
)

type TaskModel struct {
	Id      string
	Name    string
	Help    string
	Env     schema.Environment
	Desc    string
	Run     string
	Uses    string
	Args    []string
	Hosts   schema.Hosts
	Cwd     string
	Timeout time.Duration
	Needs   []string
	With    schema.With
	Force   bool
}

type TaskContext struct {
	Schema      *schema.Task
	Task        *TaskModel
	Context     context.Context
	Args        []string
	ContextName string
}

type TaskHandler func(tc TaskContext) *TaskResult

type TaskHandlerRegistry map[string]TaskHandler

var GlobalTaskHandlers = TaskHandlerRegistry{
	"ssh":                 runSshTask,
	"tmpl":                runTpl,
	"scp":                 runSCP,
	"docker":              runDocker,
	"bash":                runShell,
	"sh":                  runShell,
	"powershell":          runShell,
	"pwsh":                runShell,
	"cmd":                 runShell,
	"python":              runShell,
	"ruby":                runShell,
	"deno":                runShell,
	"node":                runShell,
	"bun":                 runShell,
	"shell":               runShell,
	"runshell":            runShell,
	"go":                  runShell,
	"golang":              runShell,
	"nushell":             runShell,
	"nu":                  runShell,
	"dotnet":              runShell,
	"docker compose up":   runComposeUp,
	"compose up":          runComposeUp,
	"docker compose down": runComposeDown,
	"compose down":        runComposeDown,
}

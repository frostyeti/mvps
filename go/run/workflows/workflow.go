package workflows

import (
	"context"
	"os"

	"github.com/frostyeti/mvps/go/run/schema"
)

type Workflow struct {
	Name         *string
	App          *string
	Path         string
	Contexts     []string
	Version      *string
	Config       *schema.RunfileConfig
	Env          *schema.Environment
	DynamicTasks map[string]schema.TaskDef
	Tasks        schema.Tasks
	Hosts        schema.Hosts
	Values       map[string]interface{}
	Args         []string
	ContextName  string
	Context      context.Context
	cleanupEnv   bool
	cleanupPath  bool
	parent       *Workflow
}

func NewWorkflow() *Workflow {

	defaultShell := os.Getenv("RUN_DEFAULT_SHELL")
	if len(defaultShell) == 0 {
		defaultShell = "bash"
		if os.Getenv("OS") == "Windows_NT" {
			defaultShell = "powershell"
		}
	}

	defaultContext := os.Getenv("RUN_CONTEXT")
	if len(defaultContext) == 0 {
		defaultContext = "default"
	}

	return &Workflow{
		Path: "",
		Config: &schema.RunfileConfig{
			Substitution: true,
			Dirs: schema.Dirs{
				Etc:      "./.run/etc",
				Projects: []string{"./.run/apps"},
			},
			Paths: schema.Paths{},
			Env:   *schema.NewEnv(),
			Shell: &defaultShell,
		},

		DynamicTasks: map[string]schema.TaskDef{},

		Env:         schema.NewEnv(),
		Values:      map[string]interface{}{},
		ContextName: defaultContext,
		Name:        nil,
		App:         nil,
		Contexts:    []string{"default"},
		Version:     nil,
		Tasks:       *schema.NewTasks(),
		Hosts:       *schema.NewHosts(),
		Args:        []string{},
		Context:     context.Background(),
		cleanupEnv:  false,
		cleanupPath: false,
	}
}

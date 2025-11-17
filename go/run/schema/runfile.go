package schema

import (
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v4"
)

/**

import:
 tasks:


**/

type Runfile struct {
	Name        string
	Import      Import
	Config      RunfileConfig
	Path        string
	Env         Environment
	DotEnv      []string
	Tasks       Tasks
	HostImports HostImports
	Values      map[string]interface{}
	Args        []string
}

func (x *Runfile) UnmarshalYAML(value *yaml.Node) error {
	if x == nil {
		x = NewRunfile()
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for runfile")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "name":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
			}
			x.Name = valueNode.Value
		case "config":
			if valueNode.Kind != yaml.MappingNode {
				return yamlErrorf(*valueNode, "expected yaml mapping for 'config' field")
			}
			if err := valueNode.Decode(&x.Config); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'config' field: %v", err)
			}
		case "env":
			if valueNode.Kind != yaml.MappingNode {
				return yamlErrorf(*valueNode, "expected yaml mapping for 'env' field")
			}
			if err := valueNode.Decode(&x.Env); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'env' field: %v", err)
			}
		case "dotenv", "dot-env", "dot_env":
			switch valueNode.Kind {
			case yaml.ScalarNode:
				x.DotEnv = []string{valueNode.Value}
			case yaml.SequenceNode:
				for _, v := range valueNode.Content {
					if v.Kind != yaml.ScalarNode {
						return yamlErrorf(*v, "expected yaml scalar in 'dotenv' array")
					}
					x.DotEnv = append(x.DotEnv, v.Value)
				}
			default:
				return yamlErrorf(*valueNode, "expected yaml scalar or array for 'dotenv' field")
			}
		case "tasks":
			if err := valueNode.Decode(&x.Tasks); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'tasks' field: %v", err)
			}
		case "hosts", "host-imports", "hostimports":
			if valueNode.Kind != yaml.MappingNode {
				return yamlErrorf(*valueNode, "expected yaml mapping for 'host_imports' field")
			}

			if err := valueNode.Decode(&x.HostImports); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'host_imports' field: %v", err)
			}
		case "values":
			if valueNode.Kind != yaml.MappingNode {
				return yamlErrorf(*valueNode, "expected yaml mapping for 'values' field")
			}
			if err := valueNode.Decode(&x.Values); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'values' field: %v", err)
			}
		default:
			// Ignore unknown fields for forward compatibility
			continue
		}
	}

	return nil
}

func NewRunfile() *Runfile {
	defaultContext := os.Getenv("RUN_CONTEXT")
	if len(defaultContext) == 0 {
		defaultContext = "default"
	}

	defaultShell := os.Getenv("RUN_SHELL")
	if len(defaultShell) == 0 {
		defaultShell = "bash"
		if os.Getenv("OS") == "Windows_NT" {
			defaultShell = "powershell"
		}
	}

	return &Runfile{
		Name: "",
		Config: RunfileConfig{
			Substitution: true,
			Dirs: Dirs{
				Etc:      "./.run/etc",
				Projects: []string{"./.run/apps"},
			},
			Paths:   Paths{},
			Env:     *NewEnv(),
			Shell:   &defaultShell,
			Context: &defaultContext,
		},
		Env:         *NewEnv(),
		DotEnv:      []string{},
		Tasks:       *NewTasks(),
		HostImports: *NewHostImports(),
		Values:      map[string]interface{}{},
	}
}

func (x *Runfile) DecodeYAMLFile(path string) error {
	if x == nil {
		x = NewRunfile()
	}

	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		path = absPath
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, x); err != nil {
		return err
	}

	x.Path = path
	return nil
}

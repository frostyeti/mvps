package schema

import (
	"os"
	"path/filepath"

	"github.com/frostyeti/mvps/go/errors"
	"go.yaml.in/yaml/v4"
)

type Step struct {
	Uses      string
	Run       string
	With      With
	Env       Environment
	Id        *string
	Name      *string
	Cwd       *string
	Desc      *string
	Force     *string
	Condition *string
}

type TaskDef struct {
	Id          string
	Name        string
	Path        string
	Author      *string
	Description *string
	Steps       []Step
	Inputs      []Input
	Outputs     []Output
}

type TaskDefs struct {
	Tasks []TaskDef
	Path  string
}

func (t *TaskDefs) DecodeYAMLFile(path string) error {
	if t == nil {
		t = &TaskDefs{}
	}

	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		path = absPath
	}

	info, err := os.Stat(path)

	if os.IsNotExist(err) {
		return errors.New("file or directory does not exist: " + path)
	}

	if info.IsDir() {
		path = filepath.Join(path, "tasks.yaml")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return errors.New("tasks.yaml file not found in directory: " + path)
		}
	}

	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		path = absPath
	}

	ext := filepath.Ext(path)
	if ext != ".yaml" && ext != ".yml" {
		return errors.New("expected a yaml file for task definitions: " + path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, t); err != nil {
		return err
	}

	t.Path = path
	return nil
}

func (s *Step) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for step")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "uses":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'uses' field")
			}
			s.Uses = valueNode.Value
		case "run":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'run' field")
			}
			s.Run = valueNode.Value
		case "with":
			var with With
			err := valueNode.Decode(&with)
			if err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'with' field: %v", err)
			}
			s.With = with
		case "env":
			var env Environment
			err := valueNode.Decode(&env)
			if err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'env' field: %v", err)
			}
			s.Env = env
		case "id":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'id' field")
			}
			id := valueNode.Value
			s.Id = &id
		case "name":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
			}
			name := valueNode.Value
			s.Name = &name
		case "cwd":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'cwd' field")
			}
			cwd := valueNode.Value
			s.Cwd = &cwd
		case "desc", "description":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'desc' field")
			}
			desc := valueNode.Value
			s.Desc = &desc
		case "force":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'force' field")
			}
			force := valueNode.Value
			s.Force = &force
		case "if", "condition":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'if' field")
			}
			condition := valueNode.Value
			s.Condition = &condition
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in step", key)
		}
	}

	return nil
}

func (t *TaskDef) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for task definition")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "id":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'id' field")
			}
			t.Id = valueNode.Value
		case "name":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
			}
			t.Name = valueNode.Value
		case "author":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'author' field")
			}
			author := valueNode.Value
			t.Author = &author
		case "description", "desc":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'description' field")
			}
			desc := valueNode.Value
			t.Description = &desc
		case "steps":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'steps' field")
			}
			for _, stepNode := range valueNode.Content {
				var step Step
				err := stepNode.Decode(&step)
				if err != nil {
					return yamlErrorf(*stepNode, "failed to decode step: %v", err)
				}
				t.Steps = append(t.Steps, step)
			}
		case "inputs":
			switch valueNode.Kind {
			case yaml.SequenceNode:
				for _, inputNode := range valueNode.Content {
					var input Input
					err := inputNode.Decode(&input)
					if err != nil {
						return yamlErrorf(*inputNode, "failed to decode input: %v", err)
					}
					t.Inputs = append(t.Inputs, input)
				}
			case yaml.MappingNode:
				for i := 0; i < len(valueNode.Content); i += 2 {
					keyNode := valueNode.Content[i]
					valueNode := valueNode.Content[i+1]

					var input Input
					err := valueNode.Decode(&input)
					if err != nil {
						return yamlErrorf(*valueNode, "failed to decode input: %v", err)
					}
					input.Id = keyNode.Value
					t.Inputs = append(t.Inputs, input)
				}
			default:
				return yamlErrorf(*valueNode, "expected yaml sequence or mapping for 'inputs' field")
			}

		case "outputs":
			switch valueNode.Kind {
			case yaml.SequenceNode:
				for _, outputNode := range valueNode.Content {
					var output Output
					err := outputNode.Decode(&output)
					if err != nil {
						return yamlErrorf(*outputNode, "failed to decode output: %v", err)
					}
					t.Outputs = append(t.Outputs, output)
				}
			case yaml.MappingNode:
				for i := 0; i < len(valueNode.Content); i += 2 {
					keyNode := valueNode.Content[i]
					valueNode := valueNode.Content[i+1]

					var output Output
					err := valueNode.Decode(&output)
					if err != nil {
						return yamlErrorf(*valueNode, "failed to decode output: %v", err)
					}
					output.Id = keyNode.Value
					t.Outputs = append(t.Outputs, output)
				}
			default:
				return yamlErrorf(*valueNode, "expected yaml sequence or mapping for 'outputs' field")
			}
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in task definition", key)
		}
	}

	return nil
}

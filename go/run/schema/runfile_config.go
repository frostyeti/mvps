package schema

import "go.yaml.in/yaml/v4"

type RunfileConfig struct {
	Paths        Paths
	Dirs         Dirs
	Env          Environment
	Substitution bool
	Context      *string
	Shell        *string
}

func (rc *RunfileConfig) UnmarshalYAML(value *yaml.Node) error {
	if rc == nil {
		rc = &RunfileConfig{}
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for runfile config")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "paths":
			var paths Paths
			err := valueNode.Decode(&paths)
			if err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'paths' field: %v", err)
			}
			rc.Paths = paths
		case "dirs":
			var dirs Dirs
			err := valueNode.Decode(&dirs)
			if err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'dirs' field: %v", err)
			}
			rc.Dirs = dirs
		case "env":
			var env Environment
			err := valueNode.Decode(&env)
			if err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'env' field: %v", err)
			}
			rc.Env = env
		case "substitution":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'substitution' field")
			}
			switch valueNode.Value {
			case "true":
				rc.Substitution = true
			case "false":
				rc.Substitution = false
			default:
				return yamlErrorf(*valueNode, "expected 'true' or 'false' for 'substitution' field")
			}
		case "context":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'context' field")
			}
			rc.Context = &valueNode.Value
		case "shell":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'shell' field")
			}
			rc.Shell = &valueNode.Value
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in runfile config", key)
		}
	}

	return nil
}

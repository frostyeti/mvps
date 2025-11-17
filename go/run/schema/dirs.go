package schema

import "go.yaml.in/yaml/v4"

type Dirs struct {
	Etc      string
	Projects []string
	Scripts  string
	Bin      string
}

func (d *Dirs) UnmarshalYAML(value *yaml.Node) error {
	if d == nil {
		d = &Dirs{}
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for dirs")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "etc":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'etc' field")
			}
			d.Etc = valueNode.Value
		case "projects":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'projects' field")
			}
			d.Projects = make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar in 'projects' list")
				}
				d.Projects = append(d.Projects, item.Value)
			}
		case "scripts":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'scripts' field")
			}
			d.Scripts = valueNode.Value
		case "bin":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'bin' field")
			}
			d.Bin = valueNode.Value
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in dirs", key)
		}
	}

	return nil
}

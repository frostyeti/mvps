package schema

import (
	"strings"

	"go.yaml.in/yaml/v4"
)

type Import struct {
	Tasks []TaskImport
}

type TaskImport struct {
	Path     string
	Checksum *string
}

func (im *Import) UnmarshalYAML(value *yaml.Node) error {
	if im == nil {
		im = &Import{}
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for import")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "tasks":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'tasks' field")
			}
			taskImports := []TaskImport{}

			for _, item := range valueNode.Content {
				if item.Kind == yaml.ScalarNode {
					path := item.Value

					taskImport := TaskImport{
						Path: path,
					}

					taskImports = append(taskImports, taskImport)

					continue
				}

				if item.Kind != yaml.MappingNode {
					return yamlErrorf(*item, "expected yaml mapping for task import")
				}

				taskImport := TaskImport{}

				for j := 0; j < len(item.Content); j += 2 {
					subKeyNode := item.Content[j]
					subValueNode := item.Content[j+1]

					subKey := subKeyNode.Value
					switch subKey {
					case "path":
						if subValueNode.Kind != yaml.ScalarNode {
							return yamlErrorf(*subValueNode, "expected yaml scalar for 'path' field")
						}
						taskImport.Path = subValueNode.Value
					case "checksum":
						if subValueNode.Kind != yaml.ScalarNode {
							return yamlErrorf(*subValueNode, "expected yaml scalar for 'checksum' field")
						}
						checksum := subValueNode.Value
						taskImport.Checksum = &checksum
					default:
						return yamlErrorf(*subKeyNode, "unexpected field '%s' in task import", subKey)
					}
				}

				taskImports = append(taskImports, taskImport)
			}
			im.Tasks = taskImports
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in import", key)
		}
	}

	return nil
}

func (ti *TaskImport) UnmarshalYAML(value *yaml.Node) error {

	if ti == nil {
		ti = &TaskImport{}
	}

	if value.Kind == yaml.ScalarNode {
		parts := strings.SplitN(value.Value, ":", 2)
		ti.Path = parts[1]
		return nil
	}

	if value.Kind == yaml.MappingNode {
		for i := 0; i < len(value.Content); i += 2 {
			keyNode := value.Content[i]
			valueNode := value.Content[i+1]

			key := keyNode.Value
			switch key {
			case "path":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'path' field")
				}
				ti.Path = valueNode.Value
			case "checksum":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'checksum' field")
				}
				checksum := valueNode.Value
				ti.Checksum = &checksum
			default:
				return yamlErrorf(*keyNode, "unexpected field '%s' in task import", key)
			}
		}

		return nil
	}

	return yamlErrorf(*value, "expected yaml scalar or mapping for task import")
}

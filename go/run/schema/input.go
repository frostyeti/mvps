package schema

import (
	"strings"

	"go.yaml.in/yaml/v4"
)

type Input struct {
	Id        string
	Name      *string
	Desc      *string
	Default   *string
	Required  *bool
	Selection []string
}

func (input *Input) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for input")
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
			input.Id = valueNode.Value
		case "name":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
			}
			name := valueNode.Value
			input.Name = &name
		case "desc", "description":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'desc' field")
			}
			desc := valueNode.Value
			input.Desc = &desc
		case "default":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'default' field")
			}
			defaultVal := valueNode.Value
			input.Default = &defaultVal
		case "required":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'required' field")
			}
			var requiredStr = strings.TrimSpace(valueNode.Value)
			if strings.EqualFold(requiredStr, "true") || requiredStr == "1" {
				required := true
				input.Required = &required
			}
		case "selection":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'selection' field")
			}
			for _, v := range valueNode.Content {
				if v.Kind != yaml.ScalarNode {
					return yamlErrorf(*v, "expected yaml scalar in 'selection' array")
				}
				trimmedVal := strings.TrimSpace(v.Value)
				input.Selection = append(input.Selection, trimmedVal)
			}
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in input", key)
		}
	}

	return nil
}

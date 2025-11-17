package schema

import "go.yaml.in/yaml/v4"

type Output struct {
	Id      string
	Desc    *string
	Default *string
}

func (o *Output) UnmarshalYAML(value *yaml.Node) error {
	if o == nil {
		o = &Output{}
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for output")
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
			o.Id = valueNode.Value
		case "desc", "description":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'description' field")
			}
			desc := valueNode.Value
			o.Desc = &desc
		case "default":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'default' field")
			}
			def := valueNode.Value
			o.Default = &def
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in output", key)
		}
	}

	return nil
}

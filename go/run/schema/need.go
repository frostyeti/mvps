package schema

import "go.yaml.in/yaml/v4"

type Need struct {
	Name     string
	Parallel bool
}

func (n *Need) UnmarshalYAML(node yaml.Node) error {
	if n == nil {
		n = &Need{}
	}

	if node.Kind == yaml.ScalarNode {
		n.Name = node.Value
		n.Parallel = false
		return nil
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			switch key {
			case "name":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
				}
				n.Name = valueNode.Value
			case "parallel":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'parallel' field")
				}
				if valueNode.Value == "true" {
					n.Parallel = true
				} else {
					n.Parallel = false
				}
			default:
				return yamlErrorf(*keyNode, "unexpected field '%s' in need", key)
			}
		}

		return nil
	}

	return yamlErrorf(node, "expected yaml scalar or mapping for 'need' node")
}

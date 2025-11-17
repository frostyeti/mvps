package schema

import "go.yaml.in/yaml/v4"

type Path struct {
	Path   string
	OS     string
	Append bool
}

type Paths []Path

func (p *Paths) UnmarshalYAML(value *yaml.Node) error {
	if (*p) == nil {
		*p = make(Paths, 0)
	}

	if value.Kind != yaml.SequenceNode {
		return yamlErrorf(*value, "expected yaml sequence for paths")
	}

	for _, item := range value.Content {
		var path Path
		if item.Kind == yaml.ScalarNode {
			path.Path = item.Value
			path.OS = ""
			path.Append = false
			*p = append(*p, path)
			continue
		}

		if item.Kind == yaml.MappingNode {
			for i := 0; i < len(item.Content); i += 2 {
				keyNode := item.Content[i]
				valueNode := item.Content[i+1]

				key := keyNode.Value
				switch key {
				case "path":
					if valueNode.Kind != yaml.ScalarNode {
						return yamlErrorf(*valueNode, "expected yaml scalar for 'path' field")
					}
					path.Path = valueNode.Value
				case "os":
					if valueNode.Kind != yaml.ScalarNode {
						return yamlErrorf(*valueNode, "expected yaml scalar for 'os' field")
					}
					path.OS = valueNode.Value
				case "append":
					if valueNode.Kind != yaml.ScalarNode {
						return yamlErrorf(*valueNode, "expected yaml scalar for 'append' field")
					}
					switch valueNode.Value {
					case "true":
						path.Append = true
					case "false":
						path.Append = false
					default:
						return yamlErrorf(*valueNode, "expected 'true' or 'false' for 'append' field")
					}
				case "win":
					fallthrough
				case "win32":
					fallthrough
				case "windows":
					path.OS = "windows"
					path.Path = valueNode.Value

				case "linux":
					path.OS = "linux"
					path.Path = valueNode.Value

				case "mac":
					fallthrough
				case "macos":
					fallthrough
				case "osx":
					fallthrough
				case "darwin":
					path.OS = "darwin"
					path.Path = valueNode.Value

				default:
					return yamlErrorf(*keyNode, "unknown field '%s' in path item", key)
				}
			}

			if path.Path == "" {
				return yamlErrorf(*item, "missing required 'path' field in path item")
			}

			*p = append(*p, path)
			continue
		}

		return yamlErrorf(*item, "expected yaml scalar or mapping for path item")
	}

	return nil
}

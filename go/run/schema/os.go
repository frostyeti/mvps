package schema

import (
	"strings"

	"go.yaml.in/yaml/v4"
)

type OS struct {
	Platform     string `yaml:"platform"`
	Arch         string `yaml:"arch"`
	Variant      string `yaml:"variant,omitempty"`
	Family       string `yaml:"family,omitempty"`
	Codename     string `yaml:"codename,omitempty"`
	Version      string `yaml:"version,omitempty"`
	BuildVersion string `yaml:"build_version,omitempty"`
}

func (o *OS) UnmarshalYAML(node yaml.Node) error {
	if o == nil {
		o = &OS{}
	}

	if node.Kind == yaml.ScalarNode {
		o.Platform = node.Value
		return nil
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			switch key {
			case "platform":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'platform' field")
				}
				o.Platform = valueNode.Value
			case "arch":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'arch' field")
				}
				o.Arch = valueNode.Value
			case "variant":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'variant' field")
				}
				o.Variant = valueNode.Value
			case "family":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'family' field")
				}
				o.Family = valueNode.Value
			case "codename":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'codename' field")
				}
				o.Codename = valueNode.Value
			case "version":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'version' field")
				}
				o.Version = valueNode.Value
			case "build_version":
				fallthrough
			case "buildVersion":
				fallthrough
			case "build-version":
				// Normalize to "build_version"
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'build_version' field")
				}
				o.BuildVersion = valueNode.Value
			default:
				return yamlErrorf(*keyNode, "unexpected field '%s' in os", key)
			}
		}
	}

	switch strings.ToLower(o.Platform) {
	case "windows":
		fallthrough
	case "win":
		fallthrough
	case "win32":
		o.Platform = "windows"
	case "linux":
		o.Platform = "linux"
	case "darwin":
		fallthrough
	case "macos":
		fallthrough
	case "mac":
		fallthrough
	case "osx":
		o.Platform = "darwin"
	default:
		return yamlErrorf(node, "unsupported platform '%s'", o.Platform)
	}

	return yamlError(node, "expected yaml scalar or mapping for 'os' node")
}

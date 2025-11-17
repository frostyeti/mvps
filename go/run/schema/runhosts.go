package schema

import (
	"maps"

	"gopkg.in/yaml.v3"
)

type RunHostsfile struct {
	Path     string                       `yaml:"path"`
	Hosts    Hosts                        `yaml:"host"`
	Defaults map[string]XHostfileDefaults `yaml:"defaults,omitempty"`
	Imports  []string                     `yaml:"imports,omitempty"`
}

type XHostfileDefaults struct {
	Port         *uint   `yaml:"port,omitempty"`
	User         *string `yaml:"user,omitempty"`
	IdentityFile *string `yaml:"identity,omitempty"`
	// this must point to an env variable that contains the password
	Password *string                `yaml:"password,omitempty"`
	Groups   []string               `yaml:"groups,omitempty"`
	Meta     map[string]interface{} `yaml:"meta,omitempty"`
	OS       *OS                    `yaml:"os,omitempty"`
}

func (f *RunHostsfile) Decode(data []byte) error {
	if f == nil {
		f = &RunHostsfile{}
	}

	err := yaml.Unmarshal(data, f)
	if err != nil {
		return err
	}

	for _, v := range f.Hosts.Entries() {
		defaultName := "default"
		if v.Defaults != "" {
			defaultName = v.Defaults
		}

		if def, ok := f.Defaults[defaultName]; ok {
			if v.Port == nil && def.Port != nil {
				v.Port = def.Port
			}
			if v.User == nil && def.User != nil {
				v.User = def.User
			}
			if v.IdentityFile == nil && def.IdentityFile != nil {
				v.IdentityFile = def.IdentityFile
			}
			if v.Password == nil && def.Password != nil {
				v.Password = def.Password
			}
			if len(v.Groups) == 0 && len(def.Groups) > 0 {
				v.Groups = def.Groups
			}

			meta := make(map[string]interface{})
			if def.Meta != nil {
				maps.Copy(meta, def.Meta)
			}

			if v.Meta != nil {
				maps.Copy(meta, v.Meta)
			}
			v.Meta = meta

			os := &OS{}
			if def.OS != nil {
				os.Arch = def.OS.Arch
				os.Family = def.OS.Family
				os.BuildVersion = def.OS.BuildVersion
				os.Codename = def.OS.Codename
				os.Platform = def.OS.Platform
				os.Variant = def.OS.Variant
				os.Version = def.OS.Version
			}

			if v.OS != nil {
				if v.OS.Arch != "" {
					os.Arch = v.OS.Arch
				}
				if v.OS.Family != "" {
					os.Family = v.OS.Family
				}
				if v.OS.BuildVersion != "" {
					os.BuildVersion = v.OS.BuildVersion
				}
				if v.OS.Codename != "" {
					os.Codename = v.OS.Codename
				}
				if v.OS.Platform != "" {
					os.Platform = v.OS.Platform
				}
				if v.OS.Variant != "" {
					os.Variant = v.OS.Variant
				}
				if v.OS.Version != "" {
					os.Version = v.OS.Version
				}
			}
		}
	}

	return nil
}

func (f *RunHostsfile) UnmarshalYAML(node *yaml.Node) error {

	if node.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		switch keyNode.Value {
		case "path":
			if valNode.Kind == yaml.ScalarNode {
				f.Path = valNode.Value
			}
		case "host":
			if valNode.Kind == yaml.MappingNode {
				if err := valNode.Decode(&f.Hosts); err != nil {
					return err
				}
			}
		case "default":
			if valNode.Kind == yaml.MappingNode {
				defaultDefaults := &XHostfileDefaults{}
				if err := valNode.Decode(defaultDefaults); err != nil {
					return err
				}
				f.Defaults["default"] = *defaultDefaults
			}
		case "defaults":
			if valNode.Kind == yaml.MappingNode {
				if err := valNode.Decode(&f.Defaults); err != nil {
					return err
				}
			}
		case "imports":
			if valNode.Kind == yaml.SequenceNode {
				if err := valNode.Decode(&f.Imports); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

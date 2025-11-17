package schema

import (
	"iter"
	"maps"
	"os"
	"runtime"
	"strings"

	om "github.com/wk8/go-ordered-map/v2"

	"go.yaml.in/yaml/v4"
)

type Environment struct {
	values  map[string]string
	keys    []string
	secrets []string
}

type environmentVariable struct {
	Name     string
	Value    string
	File     string
	IsSecret bool
}

func (ev *environmentVariable) UnmarshalYAML(node yaml.Node) error {
	if ev == nil {
		ev = &environmentVariable{}
	}

	if node.Kind == yaml.ScalarNode {
		if strings.ContainsRune(node.Value, '=') {
			parts := strings.SplitN(node.Value, "=", 2)
			ev.Name = parts[0]
			ev.Value = parts[1]
			ev.IsSecret = false
			return nil
		} else if strings.ContainsRune(node.Value, ':') {
			parts := strings.SplitN(node.Value, ":", 2)
			ev.Name = parts[0]
			ev.Value = parts[1]
			ev.IsSecret = true
			return nil
		} else {
			return yamlErrorf(node, "invalid environment variable format, expected 'KEY=VALUE' or 'KEY:VALUE'")
		}
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
				ev.Name = valueNode.Value
			case "value":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'value' field")
				}
				ev.Value = valueNode.Value
				ev.IsSecret = false
			case "secret":
				if valueNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*valueNode, "expected yaml scalar for 'secret' field")
				}
				if valueNode.Value == "true" || valueNode.Value == "1" {
					ev.IsSecret = true
				} else {
					ev.IsSecret = false
				}
			default:
				return yamlErrorf(*keyNode, "unexpected field '%s' in environment variable", key)
			}
		}

		return nil
	}

	return yamlErrorf(node, "expected yaml scalar or mapping for environment variable")
}

func (e *Environment) UnmarshalYAML(node yaml.Node) error {
	if e == nil {
		e = &Environment{}
	}

	e.values = make(map[string]string)
	e.keys = []string{}
	e.secrets = []string{}

	if node.Kind == yaml.SequenceNode {
		for _, itemNode := range node.Content {
			var ev environmentVariable
			if err := itemNode.Decode(&ev); err != nil {
				return err
			}

			var name = ev.Name
			if name == "" {
				return yamlErrorf(*itemNode, "environment variable name cannot be empty")
			}

			e.values[ev.Name] = ev.Value
			hasKey := false
			for _, k := range e.keys {
				if k == ev.Name {
					hasKey = true
					break
				}
			}
			if !hasKey {
				e.keys = append(e.keys, ev.Name)
			}
			if ev.IsSecret {
				hasSecret := false
				for _, s := range e.secrets {
					if s == ev.Name {
						hasSecret = true
						break
					}
				}
				if !hasSecret {
					e.secrets = append(e.secrets, ev.Name)
				}
			}
		}
		return nil
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			hasKey := false
			hasSecret := false

			if keyNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*keyNode, "expected yaml scalar for environment variable name")
			}
			name := keyNode.Value
			if name == "" {
				return yamlErrorf(*keyNode, "environment variable name cannot be empty")
			}

			if valueNode.Kind == yaml.ScalarNode {
				e.values[name] = valueNode.Value

				for _, k := range e.keys {
					if k == name {
						hasKey = true
						break
					}
				}
				if !hasKey {
					e.keys = append(e.keys, name)
				}

				continue
			}

			if valueNode.Kind == yaml.MappingNode {
				ev := &environmentVariable{Name: name}
				if err := valueNode.Decode(ev); err != nil {
					return err
				}

				ev.Name = name
				e.values[ev.Name] = ev.Value

				for _, k := range e.keys {
					if k == ev.Name {
						hasKey = true
						break
					}
				}

				if !hasKey {
					e.keys = append(e.keys, ev.Name)
				}

				if ev.IsSecret {
					for _, s := range e.secrets {
						if s == ev.Name {
							hasSecret = true
							break
						}
					}
					if !hasSecret {
						e.secrets = append(e.secrets, ev.Name)
					}
				}

				continue
			}

			return yamlErrorf(*valueNode, "expected yaml scalar or mapping for environment variable value")
		}

		return nil
	}

	return yamlErrorf(node, "expected yaml sequence for environment")
}

func NewEnv() *Environment {
	return &Environment{
		values:  map[string]string{},
		keys:    []string{},
		secrets: []string{},
	}
}

func NewEnvFromMap(omap om.OrderedMap[string, string]) *Environment {
	keys := []string{}
	om := map[string]string{}
	for el := omap.Oldest(); el != nil; el = el.Next() {
		om[el.Key] = el.Value
		keys = append(keys, el.Key)
	}

	return &Environment{
		values:  om,
		keys:    keys,
		secrets: []string{},
	}
}

func (e *Environment) IsSecret(key string) bool {
	e.init()

	for _, k := range e.secrets {
		if k == key {
			return true
		}
	}
	return false
}

func (e *Environment) Secrets() []string {
	e.init()
	if e.secrets == nil {
		e.secrets = []string{}
	}

	return e.secrets
}

func (e *Environment) Set(key, value string) {
	e.init()

	if _, ok := e.values[key]; !ok {
		e.keys = append(e.keys, key)
	}

	e.values[key] = value
}

func (e *Environment) Get(key string) (string, bool) {
	e.init()
	val, ok := e.values[key]
	return val, ok
}

func (e *Environment) Has(key string) bool {
	e.init()
	_, ok := e.values[key]
	return ok
}

func (e *Environment) PrependPath(path string) error {
	e.init()
	paths := e.SplitPath()

	if len(paths) > 0 {
		if runtime.GOOS == "windows" {
			if strings.EqualFold(paths[0], path) {
				return nil
			}
		} else {
			if paths[0] == path {
				return nil
			}
		}
	}

	paths = append([]string{path}, paths...)
	e.SetPath(strings.Join(paths, string(os.PathListSeparator)))
	return nil
}

func (e *Environment) AppendPath(path string) error {
	e.init()
	paths := e.SplitPath()

	if len(paths) > 0 {
		if runtime.GOOS == "windows" {
			for _, p := range paths {
				if strings.EqualFold(p, path) {
					return nil
				}
			}
		} else {
			for _, p := range paths {
				if p == path {
					return nil
				}
			}
		}
	}

	paths = append(paths, path)
	e.SetPath(strings.Join(paths, string(os.PathListSeparator)))
	return nil
}

func (e *Environment) HasPath(path string) bool {
	e.init()
	paths := e.SplitPath()
	if runtime.GOOS == "windows" {
		for _, p := range paths {
			if strings.EqualFold(p, path) {
				return true
			}
		}
		return false
	}

	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

func (e *Environment) SplitPath() []string {
	e.init()
	if e.GetPath() == "" {
		return []string{}
	}
	return strings.Split(e.GetPath(), string(os.PathListSeparator))
}

func (e *Environment) GetPath() string {
	e.init()
	if runtime.GOOS == "windows" {
		if val, ok := e.values["Path"]; ok {
			return val
		}

		return ""
	}

	if val, ok := e.values["PATH"]; ok {
		return val
	}

	return ""
}

func (e *Environment) SetPath(value string) error {
	e.init()
	if runtime.GOOS == "windows" {
		e.values["Path"] = value
		return nil
	}

	e.values["PATH"] = value
	return nil
}

func (e *Environment) GetString(key string) string {
	e.init()
	if val, ok := e.values[key]; ok {
		return val
	}
	return ""
}

func (e *Environment) Delete(key string) {
	e.init()
	delete(e.values, key)
	for i, k := range e.keys {
		if k == key {
			e.keys = append(e.keys[:i], e.keys[i+1:]...)
			break
		}
	}
}

func (e *Environment) Clone() *Environment {
	e.init()
	clone := NewEnv()

	for k, v := range e.values {
		clone.values[k] = v
	}
	clone.keys = append(clone.keys, e.keys...)
	clone.secrets = append(clone.secrets, e.secrets...)
	return clone
}

func (e *Environment) ToOrderedMap() om.OrderedMap[string, string] {
	e.init()
	om.New[string, string]()
	omap := om.New[string, string]()
	for _, k := range e.keys {
		omap.Set(k, e.values[k])
	}
	return *omap
}

func (e *Environment) ToMap() map[string]string {
	e.init()
	m := make(map[string]string, len(e.values))
	maps.Copy(m, e.values)
	return m
}

func (e *Environment) Keys() []string {
	e.init()
	keys := make([]string, 0, len(e.values))
	for k := range e.values {
		keys = append(keys, k)
	}
	return keys
}

func (e *Environment) Values() []string {
	e.init()
	values := make([]string, 0, len(e.values))
	for _, k := range e.keys {
		values = append(values, e.values[k])
	}
	return values
}

func (e *Environment) Len() int {
	if e == nil {
		return 0
	}

	e.init()
	return len(e.values)
}

// return iter.Seq
func (e *Environment) Iter() iter.Seq2[string, string] {
	e.init()
	return func(yield func(string, string) bool) {
		for _, k := range e.keys {
			if !yield(k, e.values[k]) {
				break
			}
		}
	}
}

func (e *Environment) init() {
	if e == nil {
		e = NewEnv()
	}

	if e.values == nil {
		e.values = map[string]string{}
	}

	if e.keys == nil {
		e.keys = []string{}
	}

	if e.secrets == nil {
		e.secrets = []string{}
	}
}

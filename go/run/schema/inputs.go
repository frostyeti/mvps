package schema

import (
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

type Inputs struct {
	entries map[string]interface{}
	keys    []string
}

func (e *Inputs) UnmarshalYAML(value *yaml.Node) error {
	e.init()

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for inputs")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		var v interface{}
		err := valueNode.Decode(&v)
		if err != nil {
			return yamlErrorf(*valueNode, "failed to decode input value: %v", err)
		}

		if _, ok := e.entries[key]; !ok {
			e.keys = append(e.keys, key)
		}
		e.entries[key] = v
	}

	return nil
}

func (e *Inputs) Len() int {
	if e == nil || e.entries == nil {
		return 0
	}

	return len(e.entries)
}

func (e *Inputs) Get(key string) (interface{}, bool) {
	if e == nil || e.entries == nil {
		return nil, false
	}

	entry, ok := e.entries[key]
	if ok {
		return entry, ok
	}

	for _, k := range e.keys {
		if strings.EqualFold(k, key) {
			entry, ok := e.entries[k]
			return entry, ok
		}
	}

	return nil, false
}

func (e *Inputs) Keys() []string {
	if e == nil || e.entries == nil {
		return []string{}
	}

	return e.keys
}

func (e *Inputs) TryGetKey(key ...string) (string, bool) {

	if e == nil || e.entries == nil {
		return "", false
	}

	for _, k := range key {
		if _, ok := e.entries[k]; ok {
			return k, true
		}

		for _, ek := range e.keys {
			if strings.EqualFold(ek, k) {
				return ek, true
			}

		}
	}

	return "", false
}

func (e *Inputs) TryGetValue(key ...string) (interface{}, bool) {
	if e == nil || e.entries == nil {
		return nil, false
	}

	for _, k := range key {
		if v, ok := e.entries[k]; ok {
			return v, ok
		}

		for _, ek := range e.keys {
			if strings.EqualFold(ek, k) {
				return e.entries[ek], true
			}
		}
	}

	return nil, false
}

func (e *Inputs) Set(key string, value interface{}) {
	e.init()

	if _, ok := e.entries[key]; !ok {
		e.keys = append(e.keys, key)
	}

	e.entries[key] = value
}

func (e *Inputs) TryGetBool(key ...string) (bool, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return false, false
	}

	b, ok := v.(bool)
	if ok {
		return b, ok
	}

	s, ok := v.(string)
	if !ok {
		return false, false
	}

	b, err := strconv.ParseBool(s)
	return b, err == nil
}

func (e *Inputs) TryGetInt(key ...string) (int, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return 0, false
	}

	i, ok := v.(int)
	if ok {
		return i, ok
	}

	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	i64, err := strconv.ParseInt(s, 10, 32)
	return int(i64), err == nil
}

func (e *Inputs) TryGetFloat(key ...string) (float64, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return 0, false
	}

	f, ok := v.(float64)
	if ok {
		return f, ok
	}

	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	f64, err := strconv.ParseFloat(s, 64)
	return f64, err == nil
}

func (e *Inputs) TryGetString(key ...string) (string, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return "", false
	}

	s, ok := v.(string)
	return s, ok
}

func (e *Inputs) TryGetStringSlice(key ...string) ([]string, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return []string{}, false
	}

	s, ok := v.([]string)
	return s, ok
}

func (e *Inputs) TryGetSlice(key ...string) ([]interface{}, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return []interface{}{}, false
	}

	s, ok := v.([]interface{})
	return s, ok
}

func (e *Inputs) TryGetStringMap(key ...string) (map[string]string, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return map[string]string{}, false
	}

	s, ok := v.(map[string]string)
	return s, ok
}

func (e *Inputs) TryGetMap(key ...string) (map[string]interface{}, bool) {
	v, ok := e.TryGetValue(key...)
	if !ok {
		return map[string]interface{}{}, false
	}

	s, ok := v.(map[string]interface{})
	return s, ok
}

func (e *Inputs) init() {
	if e == nil {
		e = &Inputs{
			entries: map[string]interface{}{},
			keys:    []string{},
		}
	}

}

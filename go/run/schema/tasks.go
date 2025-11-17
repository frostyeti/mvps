package schema

import (
	"strings"

	"go.yaml.in/yaml/v4"
)

type Tasks struct {
	entries map[string]Task
	keys    []string
}

func (t *Tasks) UnmarshalYAML(value *yaml.Node) error {
	t.init()

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml mapping for tasks")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		var task Task
		err := valueNode.Decode(&task)
		if err != nil {
			return yamlErrorf(*valueNode, "failed to decode task: %v", err)
		}

		if task.Id == "" {
			task.Id = key
		}

		if task.Name == nil {
			task.Name = &key
		}

		t.Set(&task)

	}

	return nil
}

func (t *Tasks) Empty() bool {
	if t == nil || t.entries == nil {
		return true
	}

	return len(t.entries) == 0
}

func (t *Tasks) Len() int {
	if t == nil || t.entries == nil {
		return 0
	}

	return len(t.entries)
}

func (t *Tasks) Get(name string) (Task, bool) {
	if t == nil || t.entries == nil {
		return Task{}, false
	}

	entry, ok := t.entries[name]
	if ok {
		return entry, ok
	}

	for _, k := range t.keys {
		if strings.EqualFold(k, name) {
			entry, ok := t.entries[k]
			return entry, ok
		}
	}

	return Task{}, false
}

func (t *Tasks) Keys() []string {
	if t == nil || t.entries == nil {
		return []string{}
	}

	return t.keys
}

func (t *Tasks) Entries() map[string]Task {
	if t == nil || t.entries == nil {
		return map[string]Task{}
	}

	return t.entries
}

func (t *Tasks) Add(entry *Task) bool {
	t.init()

	if entry == nil || entry.Id == "" {
		return false
	}

	for _, k := range t.keys {
		if strings.EqualFold(k, entry.Id) {
			return false
		}
	}

	t.keys = append(t.keys, entry.Id)
	t.entries[entry.Id] = *entry

	return true
}

func (t *Tasks) Set(entry *Task) {
	t.init()

	if entry == nil || entry.Id == "" {
		return
	}

	for _, k := range t.keys {
		if strings.EqualFold(k, entry.Id) {
			t.entries[k] = *entry
			return
		}
	}

	t.entries[entry.Id] = *entry
	t.keys = append(t.keys, entry.Id)
}

func (t *Tasks) TryGetSlice(key ...string) ([]Task, bool) {
	if t == nil || t.entries == nil {
		return nil, false
	}

	results := make([]Task, 0, len(key))
	for _, k := range key {
		s, ok := t.Get(k)
		if !ok {
			continue
		}
		results = append(results, s)
	}
	return results, len(results) > 0
}

func (t *Tasks) init() {
	if t == nil {
		t = &Tasks{
			entries: map[string]Task{},
			keys:    []string{},
		}

		return
	}

	if t.entries == nil {
		t.entries = map[string]Task{}
	}

	if t.keys == nil {
		t.keys = []string{}
	}
}

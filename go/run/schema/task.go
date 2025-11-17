package schema

import (
	"strconv"
	"strings"

	"github.com/frostyeti/mvps/go/errors"
	"go.yaml.in/yaml/v4"
)

type With map[string]interface{}

type Task struct {
	Id        string
	Desc      *string
	Help      *string
	Name      *string
	Env       *Environment
	DotEnv    []string
	Cwd       *string
	Timeout   *string
	Run       *string
	Uses      *string
	Args      []string
	Needs     []string
	With      With
	Hosts     []string
	Condition *string
	Hooks     Hooks
	Force     bool
}

func NewTasks() *Tasks {
	return &Tasks{
		entries: make(map[string]Task),
		keys:    []string{},
	}
}

func (t *Task) UnmarshalYAML(value *yaml.Node) error {
	if t == nil {
		t = &Task{}
	}

	if value.Kind == yaml.ScalarNode {
		t.Run = &value.Value
		return nil
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml scalar or mapping for task")
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
			t.Id = valueNode.Value
		case "desc":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'desc' field")
			}
			t.Desc = &valueNode.Value
		case "help":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'help' field")
			}
			t.Help = &valueNode.Value
		case "name":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'name' field")
			}
			t.Name = &valueNode.Value
		case "env":
			var env Environment
			if err := valueNode.Decode(&env); err != nil {
				return err
			}
			t.Env = &env
		case "dotenv", "envfile", "env-file":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'dotenv' field")
			}
			t.DotEnv = make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar in 'dotenv' list")
				}
				t.DotEnv = append(t.DotEnv, item.Value)
			}
		case "cwd":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'cwd' field")
			}
			t.Cwd = &valueNode.Value
		case "timeout":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'timeout' field")
			}
			t.Timeout = &valueNode.Value
		case "run":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'run' field")
			}
			t.Run = &valueNode.Value
		case "uses":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'uses' field")
			}
			t.Uses = &valueNode.Value

		case "hooks":
			hooks := Hooks{
				Before: []string{},
				After:  []string{},
			}
			if err := valueNode.Decode(&hooks); err != nil {
				return err
			}
			t.Hooks = hooks

		case "args":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'args' field")
			}
			t.Args = make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar in 'args' list")
				}
				t.Args = append(t.Args, item.Value)
			}
		case "needs", "deps", "dependencies":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'needs' field")
			}
			t.Needs = make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar in 'needs' list")
				}
				t.Needs = append(t.Needs, item.Value)
			}
		case "with", "input", "inputs":
			var with With
			if err := valueNode.Decode(&with); err != nil {
				return err
			}
			t.With = with
		case "hosts":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'hosts' field")
			}
			t.Hosts = make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar in 'hosts' list")
				}
				t.Hosts = append(t.Hosts, item.Value)
			}
		case "if", "condition":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'condition' field")
			}
			t.Condition = &valueNode.Value
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in task", key)
		}
	}

	return nil
}

func (w With) TryGetValue(key ...string) (interface{}, bool) {
	if w == nil {
		return nil, false
	}

	for _, k := range key {
		v, ok := w[k]
		if ok {
			return v, ok
		}

		for k1, v1 := range w {
			if strings.EqualFold(k1, k) {
				return v1, true
			}
		}
	}

	return nil, false
}

func (w With) TryGetString(key ...string) (string, bool) {
	v, ok := w.TryGetValue(key...)
	if !ok {
		return "", false
	}

	s, ok := v.(string)
	return s, ok
}

func (w With) TryGetBool(key ...string) (bool, bool) {
	v, ok := w.TryGetValue(key...)
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

func (w With) TryGetInt(key ...string) (int, bool) {
	v, ok := w.TryGetValue(key...)
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

func (w With) TryGetFloat(key ...string) (float64, bool) {
	v, ok := w.TryGetValue(key...)
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
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func (w With) TryGetStringSlice(key ...string) ([]string, bool) {
	v, ok := w.TryGetValue(key...)
	if !ok {
		return nil, false
	}

	ss, ok := v.([]string)
	if ok {
		return ss, ok
	}

	sa, ok := v.([]interface{})
	if !ok {
		return nil, false
	}

	results := make([]string, 0, len(sa))
	for _, item := range sa {
		s, ok := item.(string)
		if !ok {
			continue
		}
		results = append(results, s)
	}

	if len(results) == 0 {
		return nil, false
	}

	return results, true
}

func (w With) TryGetMap(key ...string) (map[string]interface{}, bool) {
	v, ok := w.TryGetValue(key...)
	if !ok {
		return nil, false
	}

	m, ok := v.(map[string]interface{})
	return m, ok
}

func (w With) Keys() []string {
	if w == nil {
		return []string{}
	}

	keys := make([]string, 0, len(w))
	for k := range w {
		keys = append(keys, k)
	}
	return keys
}

func (w With) Len() int {
	if w == nil {
		return 0
	}
	return len(w)
}

func (w With) TryGetSlice(key ...string) ([]interface{}, bool) {
	v, ok := w.TryGetValue(key...)
	if !ok {
		return nil, false
	}

	sa, ok := v.([]interface{})
	if !ok {
		return nil, false
	}

	if len(sa) == 0 {
		return nil, false
	}

	return sa, true
}

func (w With) ToMap() map[string]interface{} {
	if w == nil {
		return map[string]interface{}{}
	}

	m := make(map[string]interface{}, len(w))
	for k, v := range w {
		m[k] = v
	}
	return m
}

func (t *Tasks) FlattenTasks(targets []string, context string) ([]Task, error) {
	return FlattenTasks(targets, *t, []Task{}, context)
}

func FlattenTasks(targets []string, tasks Tasks, set []Task, context string) ([]Task, error) {

	for _, target := range targets {
		t := target

		var task Task
		found := false

		// prefer context-specific task if context is provided and it is found.
		if context != "" {
			t = target + ":" + context
			task2, ok := tasks.Get(t)
			if ok {
				task = task2
				found = true
			}
		}

		if !found {
			t = target
			task2, ok := tasks.Get(t)
			if !ok {
				return nil, errors.New("Task not found: " + target + " or " + t)
			}

			task = task2
		}

		// ensure dependencies are added first
		if len(task.Needs) > 0 {
			neededTasks, err := FlattenTasks(task.Needs, tasks, set, context)
			if err != nil {
				return nil, err
			}
			set = neededTasks
		}

		// Treat hooks as something that always must be added around the main task
		// even if they were already added as part of dependencies.

		// only add before hooks if they task is setup for hooks
		if len(task.Hooks.Before) > 0 {
			for _, beforeHookSuffix := range task.Hooks.Before {
				// use task.Id to ensure that context-specific hooks are resolved
				// if the main task is context-specific, otherwise use the base task.
				hookTaskName := task.Id + ":" + beforeHookSuffix
				beforeTask, ok := tasks.Get(hookTaskName)
				if ok {
					set = append(set, beforeTask)
				}
			}
		}

		added := false
		for _, task2 := range set {
			if task.Id == task2.Id {
				added = true
				break
			}
		}

		if !added {
			set = append(set, task)
		}

		// only add after hooks if they task is setup for hooks
		if len(task.Hooks.After) > 0 {
			for _, afterHookSuffix := range task.Hooks.After {
				// use task.Id to ensure that context-specific hooks are resolved
				// if the main task is context-specific, otherwise use the base task.
				hookTaskName := task.Id + ":" + afterHookSuffix
				afterTask, ok := tasks.Get(hookTaskName)
				if ok {
					set = append(set, afterTask)
				}
			}
		}
	}

	return set, nil
}

func FindCyclicalReferences(tasks []Task) []Task {
	stack := []Task{}
	cycles := []Task{}

	var resolve func(task Task) bool
	resolve = func(task Task) bool {
		for _, t := range stack {
			if task.Id == t.Id {
				return false
			}
		}

		stack = append(stack, task)

		if len(task.Needs) > 0 {
			for _, need := range task.Needs {
				for _, nextTask := range tasks {
					if nextTask.Id == need {
						if !resolve(nextTask) {
							return false
						}
					}
				}
			}
		}

		stack = stack[:len(stack)-1]
		return true
	}

	for _, task := range tasks {
		if !resolve(task) {
			cycles = append(cycles, task)
		}
	}

	return cycles
}

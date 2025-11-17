package workflows

import (
	"github.com/frostyeti/mvps/go/run/schema"
)

func (wf *Workflow) List() []schema.Task {
	if wf == nil {
		return []schema.Task{}
	}

	tasks := []schema.Task{}
	for _, task := range wf.Tasks.Entries() {
		tasks = append(tasks, task)
	}

	return tasks
}

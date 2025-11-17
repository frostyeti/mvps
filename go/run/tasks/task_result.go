package tasks

import (
	"time"

	"github.com/frostyeti/mvps/go/errors"
	"github.com/frostyeti/mvps/go/run/tasks/statuses"
)

type TaskResult struct {
	Err       error
	Status    int
	StartedAt time.Time
	EndedAt   time.Time
	Message   string
	Output    map[string]interface{}
}

func (tr *TaskResult) Start() *TaskResult {
	tr.StartedAt = time.Now().UTC()
	return tr
}

func (tr *TaskResult) End() *TaskResult {
	tr.EndedAt = time.Now().UTC()
	return tr
}

func (tr *TaskResult) Ok() *TaskResult {
	tr.Status = statuses.Ok
	tr.End()
	return tr
}

func (tr *TaskResult) Fail(err error) *TaskResult {
	tr.Err = errors.WithCause(err, tr.Err)
	tr.Status = statuses.Error
	tr.End()
	return tr
}

func (tr *TaskResult) Skip(msg string) *TaskResult {
	tr.Status = statuses.Skipped
	tr.Message = msg
	tr.End()
	return tr
}

func (tr *TaskResult) Cancel(msg string) *TaskResult {
	tr.Status = statuses.Cancelled
	tr.Message = msg
	tr.End()
	return tr
}

func NewTaskResult() *TaskResult {
	return &TaskResult{
		Err:       nil,
		Status:    statuses.None,
		StartedAt: time.Now().UTC(),
		EndedAt:   time.Now().UTC(),
		Message:   "",
		Output:    make(map[string]interface{}),
	}
}

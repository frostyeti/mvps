package schema

import (
	"fmt"

	"github.com/frostyeti/mvps/go/errors"
	"go.yaml.in/yaml/v4"
)

type CyclicalReferenceError struct {
	Cycles []Task
}

func (e *CyclicalReferenceError) Error() string {
	msg := "Cyclical references found in tasks:\n"
	for _, cycle := range e.Cycles {
		msg += " - " + cycle.Id + "\n"
	}
	return msg
}

func yamlError(node yaml.Node, message string) error {
	msg := fmt.Sprintf("%s on line %d, at column %d", message, node.Line, node.Column)

	return errors.NewDetails(msg, "YamlError", msg)
}

func yamlErrorf(node yaml.Node, format string, args ...interface{}) error {
	return yamlError(node, fmt.Sprintf(format, args...))
}

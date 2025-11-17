package tasks

import (
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/Masterminds/sprig"
	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/errors"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/tasks/statuses"
)

func RegisterDynamicTask(id string, taskDef schema.TaskDef) error {
	_, exists := GlobalTaskHandlers[id]
	if exists {
		return nil
	}

	runTaskFile := taskDef.Path
	dir := filepath.Dir(taskDef.Path)
	runTaskDir := dir

	handler := func(ctx TaskContext) *TaskResult {
		res := NewTaskResult()

		f, err := os.CreateTemp("", "run-outputs-")
		if err != nil {
			return res.Fail(err)
		}
		f.Write([]byte{})
		f.Close()

		taskEnv := schema.NewEnv()
		for k, v := range ctx.Task.Env.ToMap() {
			taskEnv.Set(k, v)
		}

		taskEnv.Set("RUN_TASK_DIR", runTaskDir)
		taskEnv.Set("RUN_TASK_FILE", runTaskFile)
		taskEnv.Set("RUN_TASK_NAME", taskDef.Name)
		taskEnv.Set("RUN_TASK_ID", ctx.Task.Id)
		taskEnv.Set("RUN_TASK_CWD", ctx.Task.Cwd)

		taskEnv.Set("RUN_OUTPUTS", f.Name())

		defer func() {
			// if file exists, remove it
			if _, err := os.Stat(f.Name()); err == nil {
				os.Remove(f.Name())
			}
		}()

		for _, inputDef := range taskDef.Inputs {
			inputValue, ok := ctx.Task.With.TryGetString(inputDef.Id)
			required := false
			if inputDef.Required != nil {
				required = *inputDef.Required
			}

			defaultValue := ""
			if inputDef.Default != nil {
				defaultValue = *inputDef.Default
			}

			if !ok && defaultValue != "" {
				inputValue = defaultValue
				ok = true
			}

			if required && !ok {
				return res.Fail(errors.New("Missing required input: " + inputDef.Id))
			}

			if len(inputDef.Selection) > 0 {

				valid := false
				for _, option := range inputDef.Selection {
					if option == inputValue {
						valid = true
						break
					}
				}

				if !valid {
					return res.Fail(errors.New("Invalid value for input " + inputDef.Id))
				}
			}

			envName := "INPUT_" + string(ScreamingCase([]rune(inputDef.Id)))
			taskEnv.Set(envName, inputValue)
		}

		results := []TaskResult{}
		failed := false

		for i, step := range taskDef.Steps {
			nextRes := NewTaskResult()

			if step.Id == nil {
				id := ctx.Task.Id + ".step-" + strconv.Itoa(i+1)
				step.Id = &id
			}

			stepId := *step.Id

			if step.Name == nil {
				name := "Step " + strconv.Itoa(i+1)
				step.Name = &name
			}

			taskEnv.Set("RUN_STEP_ID", *step.Id)
			taskEnv.Set("RUN_STEP_NAME", *step.Name)
			taskEnv.Set("RUN_STEP_INDEX", strconv.Itoa(i))

			uses := step.Uses

			if uses == "" {
				nextRes.Fail(errors.New("Step " + *step.Id + " is missing 'uses' field"))
				results = append(results, *nextRes)
				continue
			}

			if strings.Contains(uses, "://") {
				uri, err := url.Parse(uses)

				if err != nil {
					nextRes.Fail(errors.New("Invalid template URI: " + err.Error()))
					results = append(results, *nextRes)
					continue
				}

				uses = uri.Scheme
			}

			handler, ok := GlobalTaskHandlers[uses]
			if !ok {
				nextRes.Fail(errors.New("Step " + *step.Id + " has unsupported 'uses' value: " + uses))
				results = append(results, *nextRes)
				continue
			}

			envOptions := &env.ExpandOptions{
				Get: func(key string) string {
					s, ok := taskEnv.Get(key)
					if ok {
						return s
					}

					return ""
				},
				Set: func(key, value string) error {
					taskEnv.Set(key, value)
					return nil
				},
				Keys:                taskEnv.Keys(),
				CommandSubstitution: true,
			}

			cwd := ctx.Task.Cwd
			if step.Cwd != nil {
				cwd = *step.Cwd
				cwd, err = env.ExpandWithOptions(cwd, envOptions)
				if err != nil {
					nextRes.Fail(errors.New("Failed to expand cwd: " + err.Error()))
					results = append(results, *nextRes)
					continue
				}

				if !filepath.IsAbs(cwd) {
					p, err := filepath.Abs(filepath.Join(runTaskDir, cwd))
					if err != nil {
						nextRes.Fail(errors.New("Failed to resolve cwd: " + err.Error()))
						results = append(results, *nextRes)
						continue
					}
					cwd = p
				}
			}

			taskEnv.Set("RUN_STEP_CWD", cwd)

			run := step.Run
			runTrimmed := strings.TrimSpace(run)

			if cwd != ctx.Task.Cwd {
				os.Chdir(cwd)

				defer func() {
					os.Chdir(ctx.Task.Cwd)
				}()
			}

			// must be a file path and a single line, and not an absolute path
			if len(runTrimmed) > 0 && !strings.ContainsAny(runTrimmed, "\n\r") {
				ext := filepath.Ext(runTrimmed)
				if ext != "" && !filepath.IsAbs(runTrimmed) {

					if cwd != runTaskDir {
						os.Chdir(runTaskDir)
						p, _ := filepath.Abs(runTrimmed)
						run = p
						os.Chdir(cwd)
					} else {
						p, _ := filepath.Abs(runTrimmed)
						run = p
					}
				}
			}

			step.Run = run

			desc := ""
			if step.Desc != nil {
				desc = *step.Desc
			}

			forceString := ""
			force := false
			if step.Force != nil {
				forceString = *step.Force
				if len(forceString) > 0 {
					predicateRaw := forceString
					if predicateRaw == "0" || strings.EqualFold(predicateRaw, "false") {
						force = false
					} else if predicateRaw == "1" || strings.EqualFold(predicateRaw, "true") {
						force = true
					} else {
						force = false

						tplData := map[string]interface{}{
							"env":  taskEnv.ToMap(),
							"os":   runtime.GOOS,
							"arch": runtime.GOARCH,
						}

						tmp, err := template.New(stepId + "." + "if").Funcs(sprig.FuncMap()).Parse(predicateRaw)
						if err != nil {
							nextRes.Fail(errors.New("failed to parse if section for step " + stepId + ": " + err.Error()))
							results = append(results, *nextRes)
							continue
						}

						out := &strings.Builder{}
						if err := tmp.Execute(out, tplData); err != nil {
							nextRes.Fail(errors.New("failed to execute template for step " + stepId + ": " + err.Error()))
							results = append(results, *nextRes)
							continue
						}

						output := strings.TrimSpace(out.String())
						if output == "1" || strings.EqualFold(output, "true") {
							force = true
						}
					}
				}
			}

			conditionString := ""
			condition := true
			if step.Condition != nil {
				conditionString = *step.Condition
				if len(conditionString) > 0 {
					predicateRaw := conditionString
					if predicateRaw == "0" || strings.EqualFold(predicateRaw, "false") {
						condition = false
					} else if predicateRaw == "1" || strings.EqualFold(predicateRaw, "true") {
						condition = true
					} else {
						condition = true
						tplData := map[string]interface{}{
							"env":  taskEnv.ToMap(),
							"os":   runtime.GOOS,
							"arch": runtime.GOARCH,
						}

						tmp, err := template.New(stepId + "." + "if").Funcs(sprig.FuncMap()).Parse(predicateRaw)
						if err != nil {
							nextRes.Fail(errors.New("failed to parse if section for step " + stepId + ": " + err.Error()))
							results = append(results, *nextRes)
							continue
						}

						out := &strings.Builder{}
						if err := tmp.Execute(out, tplData); err != nil {
							nextRes.Fail(errors.New("failed to execute template for step " + stepId + ": " + err.Error()))
							results = append(results, *nextRes)
							continue
						}

						output := strings.TrimSpace(out.String())
						if output == "1" || strings.EqualFold(output, "true") {
							condition = true
						}
					}
				}
			}

			if !condition {
				nextRes.Skip("condition was false")
				continue
			}

			if failed && !force {
				nextRes.Skip("previous step failed and force is false")
				continue
			}

			nextTask := &TaskModel{
				Id:      *step.Id,
				Name:    *step.Name,
				Uses:    step.Uses,
				Run:     step.Run,
				With:    step.With,
				Env:     *taskEnv,
				Cwd:     cwd,
				Desc:    desc,
				Args:    ctx.Task.Args,
				Timeout: ctx.Task.Timeout,
				Force:   force,
				Hosts:   ctx.Task.Hosts,
				Needs:   ctx.Task.Needs,
			}

			nextCtx := TaskContext{
				Task:        nextTask,
				Context:     ctx.Context,
				Args:        ctx.Args,
				Schema:      ctx.Schema,
				ContextName: ctx.ContextName,
			}

			res2 := handler(nextCtx)
			if res2.Status == statuses.Error {
				failed = true
			}

			results = append(results, *res2)
		}

		file := taskEnv.GetString("RUN_OUTPUTS")
		if len(file) > 0 {
			outputBytes, err := os.ReadFile(file)

			if err != nil {
				return res.Fail(errors.New("Failed to read outputs file: " + err.Error()))
			}

			outputStr := string(outputBytes)
			doc, err := dotenv.Parse(outputStr)
			if err != nil {
				return res.Fail(errors.New("Failed to parse outputs file: " + err.Error()))
			}

			outputMap := doc.ToMap()
			for k, v := range outputMap {
				outputName := strings.ToLower(k)
				outputName = strings.ReplaceAll(outputName, "_", "-")
				res.Output[outputName] = v
			}
		}

		if failed {
			builder := &strings.Builder{}
			builder.WriteString("Task " + ctx.Task.Id + " failed: \n")
			for _, r := range results {
				if r.Status == statuses.Error {
					builder.WriteString(r.Err.Error() + "\n")
				}
			}

			return res.Fail(errors.New(builder.String()))
		}

		return res.Ok()
	}

	GlobalTaskHandlers[id] = handler
	return nil
}

func ScreamingCase(runes []rune) []rune {
	if len(runes) == 0 {
		return runes
	}

	sb := make([]rune, 0)
	last := rune(0)

	for _, r := range runes {
		if unicode.IsLetter(r) {
			if unicode.IsUpper(r) {
				if unicode.IsLetter(last) && unicode.IsLower(last) {
					sb = append(sb, '_')

				}

				sb = append(sb, r)
				last = r
				continue
			}

			sb = append(sb, unicode.ToUpper(r))
			last = r
			continue
		}

		if unicode.IsNumber(r) {
			sb = append(sb, r)
			last = r
			continue
		}

		if r == '_' || r == '-' || unicode.IsSpace(r) {
			if len(sb) == 0 {
				continue
			}

			if last == '_' {
				continue
			}

			last = '_'
			sb = append(sb, last)
			continue
		}

	}

	if len(sb) > 0 && sb[len(sb)-1] == '_' {
		sb = sb[:len(sb)-1]
	}

	return sb
}

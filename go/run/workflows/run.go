package workflows

import (
	"bufio"
	"errors"
	"html/template"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/tasks"
)

func (ws *Workflow) Run(taskNames []string, args []string) error {
	if ws == nil {
		return errors.New("workflow is nil")
	}

	if len(taskNames) == 0 {
		taskNames = []string{"default"}
	}

	allTasks := []schema.Task{}

	for _, target := range ws.Tasks.Entries() {
		allTasks = append(allTasks, target)
	}

	cycles := schema.FindCyclicalReferences(allTasks)
	if len(cycles) > 0 {
		return &CyclicalReferenceError{Cycles: cycles}
	}

	contextName := ws.ContextName
	if len(contextName) == 0 {
		contextName = "default"
	}

	flatTasks, err := ws.Tasks.FlattenTasks(taskNames, contextName)
	if err != nil {
		return err
	}

	// skip last task if there is more than one task and
	// the last task has no run or uses defined
	lastId := ""
	if len(flatTasks) > 1 {
		last := flatTasks[len(flatTasks)-1]
		if last.Uses == nil || len(*last.Uses) == 0 {

			if last.Run == nil || len(*last.Run) == 0 {
				lastId = last.Id

			}
		}
	}

	if ws.cleanupEnv {
		envFile := ws.Env.GetString("RUN_ENV")
		if len(envFile) > 0 {
			defer func() {
				if isFile(envFile) {
					os.Remove(envFile)
				}
			}()
		}
	}

	if ws.cleanupPath {
		pathFile := ws.Env.GetString("RUN_PATH")
		if len(pathFile) > 0 {
			defer func() {
				if isFile(pathFile) {
					os.Remove(pathFile)
				}
			}()
		}
	}

	envMap := ws.Env.Clone()
	if envMap.Has("RUN_ENV") && !ws.cleanupEnv {
		envFile := envMap.GetString("RUN_ENV")
		if len(envFile) > 0 {
			canOpen := true
			if _, err := os.Stat(envFile); err != nil {
				canOpen = false
			}

			if canOpen {
				bytes, err := os.ReadFile(envFile)
				if err != nil {
					return errors.New("Failed to read RUN_ENV file: " + err.Error())
				}

				if len(bytes) > 0 {
					opts := &env.ExpandOptions{
						Get: func(key string) string {
							val, ok := envMap.Get(key)
							if ok {
								return val
							}
							return ""
						},
						Set: func(key, value string) error {
							envMap.Set(key, value)
							return nil
						},
						Keys:                envMap.Keys(),
						ExpandUnixArgs:      true,
						ExpandWindowsVars:   false,
						CommandSubstitution: ws.Config.Substitution,
					}
					doc2, err := dotenv.Parse(string(bytes))
					if err != nil {
						return errors.New("Failed to parse RUN_ENV file: " + err.Error())
					}

					for _, node := range doc2.ToArray() {
						if node.Type == dotenv.VARIABLE_TOKEN {
							key := ""
							value := node.Value
							if node.Key != nil {
								key = *node.Key
							}

							if strings.HasPrefix("RUN_", key) {
								if strings.HasSuffix(key, "_EXE") {
									value, err := env.ExpandWithOptions(value, opts)
									if err != nil {
										return errors.New("Failed to expand environment variable: " + err.Error())
									}

									envMap.Set(key, value)
								}
								continue
							}

							value, err := env.ExpandWithOptions(value, opts)
							if err != nil {
								return errors.New("Failed to expand environment variable: " + err.Error())
							}
							envMap.Set(key, value)
						}
					}
				}
			}
		}
	}

	hostGroups := map[string][]schema.HostEntry{}
	for name, host := range ws.Hosts.Entries() {
		if len(host.Groups) > 0 {
			for _, group := range host.Groups {
				if _, ok := hostGroups[group]; !ok {
					hostGroups[group] = []schema.HostEntry{}
				}
				hostGroups[group] = append(hostGroups[group], host)
			}
		}

		if _, ok := hostGroups[name]; !ok {
			hostGroups[name] = []schema.HostEntry{host}
		} else {
			hostGroups[name] = append(hostGroups[name], host)
		}
	}

	for _, task := range flatTasks {
		taskEnv := envMap.Clone()

		if lastId != "" && task.Id == lastId {
			name := task.Id
			if task.Name != nil && len(*task.Name) > 0 {
				name = *task.Name
			}

			os.Stdout.WriteString("\x1b[1m" + name + "\x1b[22m\n")
			return nil
		}

		f, err := os.CreateTemp("", "run-env-")
		if err != nil {
			return err
		}
		f.Write([]byte{})
		f.Close()
		taskEnv.Set("RUN_ENV", f.Name())

		defer func() {
			if isFile(f.Name()) {
				os.Remove(f.Name())
			}
		}()

		f2, err := os.CreateTemp("", "run-path-")
		if err != nil {
			return err
		}
		f2.Write([]byte{})
		f2.Close()
		taskEnv.Set("RUN_PATH", f2.Name())

		defer func() {
			if isFile(f2.Name()) {
				os.Remove(f2.Name())
			}
		}()

		if task.Name == nil || len(*task.Name) == 0 {
			task.Name = &task.Id
		}

		uses := ws.Config.Shell
		if task.Uses != nil && len(*task.Uses) > 0 {
			uses = task.Uses
		}

		desc := ""
		if task.Desc != nil {
			desc = *task.Desc
		}

		help := ""
		if task.Help != nil {
			help = *task.Help
		}

		cwd := ""
		if task.Cwd != nil && len(*task.Cwd) > 0 {
			cwd = *task.Cwd
		}
		if len(cwd) == 0 {
			c, ok := ws.Env.Get("RUN_DIR")
			if ok {
				cwd = c
			} else {
				c, err := os.Getwd()
				if err != nil {
					return err
				}
				cwd = c
			}
		}

		var timeout time.Duration
		timeout = 0
		if task.Timeout != nil && len(*task.Timeout) > 0 {
			t, err := time.ParseDuration(*task.Timeout)
			if err != nil {
				return err
			}
			timeout = t
		}

		run := ""
		if task.Run != nil && len(*task.Run) > 0 {
			run = *task.Run
		}

		hosts := schema.NewHosts()
		if len(task.Hosts) > 0 {
			for _, h := range task.Hosts {
				if groupHosts, ok := hostGroups[h]; ok {
					for _, gh := range groupHosts {
						hosts.Set(h, &gh)
					}
				}
			}
		}

		opts := &env.ExpandOptions{
			Get: func(key string) string {
				val, ok := taskEnv.Get(key)
				if ok {
					return val
				}
				return ""
			},
			Set: func(key, value string) error {
				taskEnv.Set(key, value)
				return nil
			},
			Keys:                taskEnv.Keys(),
			ExpandUnixArgs:      true,
			ExpandWindowsVars:   false,
			CommandSubstitution: ws.Config.Substitution,
		}

		if task.Env.Len() > 0 {

			for k, v := range task.Env.Iter() {

				ev, err := env.ExpandWithOptions(v, opts)
				if err != nil {
					return errors.New("failed to expand env var: " + k + " for task: " + task.Id + " error: " + err.Error())
				}
				taskEnv.Set(k, ev)
				hasKey := false
				for _, keys := range opts.Keys {
					if keys == k {
						hasKey = true
						break
					}
				}

				if !hasKey {
					opts.Keys = append(opts.Keys, k)
				}
			}
		}

		if strings.ContainsRune(cwd, '$') {
			c, err := env.ExpandWithOptions(cwd, opts)
			if err != nil {
				return errors.New("failed to expand cwd: " + cwd + " for task: " + task.Id + " error: " + err.Error())
			}
			cwd = c
		}

		data := &tasks.TaskModel{
			Env:     *taskEnv,
			Id:      task.Id,
			Hosts:   *hosts,
			Uses:    *uses,
			Desc:    desc,
			Help:    help,
			Run:     run,
			Needs:   task.Needs,
			With:    task.With,
			Cwd:     cwd,
			Timeout: timeout,
		}

		taskCtx := &tasks.TaskContext{
			Schema:      &task,
			Task:        data,
			Args:        args,
			Context:     ws.Context,
			ContextName: ws.ContextName,
		}

		name := data.Id
		if task.Name != nil && len(*task.Name) > 0 {
			name = *task.Name
		}

		predicate := true
		if task.Condition != nil && len(*task.Condition) > 0 {
			predicateRaw := *task.Condition
			if predicateRaw == "0" || strings.EqualFold(predicateRaw, "false") {
				predicate = false
			} else if predicateRaw == "1" || strings.EqualFold(predicateRaw, "true") {
				predicate = true
			} else {
				predicate = false
			}

			tplData := map[string]interface{}{
				"env":  taskEnv.ToMap(),
				"os":   runtime.GOOS,
				"arch": runtime.GOARCH,
			}

			tmp, err := template.New(task.Id + "." + "if").Funcs(sprig.FuncMap()).Parse(predicateRaw)
			if err != nil {
				return errors.New("failed to parse if section for task " + task.Id + ": " + err.Error())
			}

			out := &strings.Builder{}
			if err := tmp.Execute(out, tplData); err != nil {
				return errors.New("failed to execute template for task " + task.Id + ": " + err.Error())
			}

			output := strings.TrimSpace(out.String())
			if output == "1" || strings.EqualFold(output, "true") {
				predicate = true
			}
		}

		if !predicate {
			os.Stdout.WriteString("\x1b[1m" + name + "\x1b[22m (skipped)\n")
			continue
		}

		os.Stdout.WriteString("\x1b[1m" + name + "\x1b[22m\n")
		result := tasks.Run(*taskCtx)

		if result.Err != nil {
			return result.Err
		}

		envFile := taskEnv.GetString("RUN_ENV")
		if len(envFile) > 0 {
			canOpen := true
			if _, err := os.Stat(envFile); err != nil {
				canOpen = false
			}

			if canOpen {
				bytes, err := os.ReadFile(envFile)
				if err != nil {
					return errors.New("Failed to read RUN_ENV file: " + err.Error())
				}

				if len(bytes) > 0 {
					opts := &env.ExpandOptions{
						Get: func(key string) string {
							val, ok := envMap.Get(key)
							if ok {
								return val
							}
							return ""
						},
						Set: func(key, value string) error {
							envMap.Set(key, value)
							return nil
						},
						Keys:                envMap.Keys(),
						ExpandUnixArgs:      true,
						ExpandWindowsVars:   false,
						CommandSubstitution: ws.Config.Substitution,
					}
					doc2, err := dotenv.Parse(string(bytes))
					if err != nil {
						return errors.New("Failed to parse RUN_ENV file: " + err.Error())
					}

					for _, node := range doc2.ToArray() {
						if node.Type == dotenv.VARIABLE_TOKEN {
							key := ""
							value := node.Value
							if node.Key != nil {
								key = *node.Key
							}

							if strings.HasPrefix("RUN_", key) {
								if strings.HasSuffix(key, "_EXE") {
									value, err := env.ExpandWithOptions(value, opts)
									if err != nil {
										return errors.New("Failed to expand environment variable: " + err.Error())
									}

									envMap.Set(key, value)
								}
								continue
							}

							value, err := env.ExpandWithOptions(value, opts)
							if err != nil {
								return errors.New("Failed to expand environment variable: " + err.Error())
							}
							envMap.Set(key, value)
						}
					}
				}
			}

			if isFile(envFile) {
				os.Remove(envFile)
			}
		}

		pathFile := taskEnv.GetString("RUN_PATH")
		if len(pathFile) > 0 {

			canOpen := true
			if _, err := os.Stat(pathFile); err != nil {
				canOpen = false
			}

			if canOpen {
				bytes, err := os.ReadFile(pathFile)
				if err != nil {
					return errors.New("Failed to read RUN_PATH file: " + err.Error())
				}

				if len(bytes) > 0 {
					content := string(bytes)
					scanner := bufio.NewScanner(strings.NewReader(content))
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if len(line) > 0 {
							if _, err := os.Stat(line); err == nil {
								// LAST IN SHOULD BE FIRST IN PATH
								envMap.PrependPath(line)
							}
						}
					}
				}
			}

			if isFile(pathFile) {
				os.Remove(pathFile)
			}
		}
	}

	return nil
}

package workflows

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/frostyeti/mvps/go/run/schema"
)

func (wf *Workflow) RunLifecycle(target string, app string, contextName string) error {

	find := map[string]string{}
	taskMap := wf.Tasks.Entries()
	for key := range taskMap {
		if key == target || strings.HasPrefix(key, target+":") {
			find[key] = key
		}
	}
	targets := []string{}
	if app == "" || app == "default" {
		testFound := false
		if _, ok := taskMap[target+":default:"+contextName+":before"]; ok {
			targets = append(targets, target+":default:"+contextName+":before")
		} else if _, ok := taskMap[target+":default:before"]; ok {
			targets = append(targets, target+":default:before")
		} else if _, ok := taskMap[target+":before"]; ok {
			targets = append(targets, target+":before")
		}

		if _, ok := taskMap[target+":default:"+contextName]; ok {
			targets = append(targets, target+":default:"+contextName)
			testFound = true
		} else if _, ok := taskMap[target+":default"]; ok {
			targets = append(targets, target+":default")
			testFound = true
		} else if _, ok := taskMap[target]; ok {
			targets = append(targets, target)
			testFound = true
		}

		if _, ok := taskMap[target+":default:"+contextName+":after"]; ok {
			targets = append(targets, target+":default:"+contextName+":after")
		} else if _, ok := taskMap[target+":default:after"]; ok {
			targets = append(targets, target+":default:after")
		} else if _, ok := taskMap[target+":after"]; ok {
			targets = append(targets, target+":after")
		}

		if !testFound {
			return errors.New("no default test task found")
		}

	} else {
		targetFound := false

		if _, ok := find[target+":"+app+":"+contextName+":before"]; ok {
			targets = append(targets, target+":"+app+":"+contextName+":before")
		} else if _, ok := taskMap[target+":"+app+":before"]; ok {
			targets = append(targets, target+":"+app+":before")
		} else if _, ok := taskMap[target+":before"]; ok {
			targets = append(targets, target+":before")
		}

		if _, ok := find[target+":"+app+":"+contextName]; ok {
			targets = append(targets, target+":"+app+":"+contextName)
			targetFound = true
		} else if _, ok := taskMap[target+":"+app]; ok {
			targets = append(targets, target+":"+app)
			targetFound = true
		}

		if _, ok := taskMap[target+":"+app+":"+contextName+":after"]; ok {
			targets = append(targets, target+":"+app+":"+contextName+":after")
		} else if _, ok := taskMap[target+":"+app+":after"]; ok {
			targets = append(targets, target+":"+app+":after")
		} else if _, ok := taskMap[target+":after"]; ok {
			targets = append(targets, target+":after")
		}

		if wf.parent != nil && !targetFound {
			return errors.New("no " + target + " task found for app: " + app + " in workflow")
		}

		if !targetFound {
			apps := wf.Config.Dirs.Projects
			slices.Reverse(apps)

			og, err := os.Getwd()
			if err != nil {
				return err
			}

			baseDir := wf.Env.GetString("RUN_DIR")
			if baseDir != "" && baseDir != og {
				os.Chdir(baseDir)
				defer os.Chdir(og)
			}

			nextTaskfile := ""

			for _, dir := range apps {
				dir = strings.TrimSpace(strings.TrimRight(dir, "*"))

				if !filepath.IsAbs(dir) {
					resolved, err := filepath.Abs(dir)
					if err != nil {
						return err
					}
					dir = resolved
				}

				basename := filepath.Base(dir)
				if strings.EqualFold(basename, app) {
					try := filepath.Join(dir, contextName, "runfile")
					if isFile(try) {
						nextTaskfile = try
						break
					}

					try = filepath.Join(dir, "runfile")
					if isFile(try) {
						nextTaskfile = try
						break
					}
				}

				try := filepath.Join(dir, app, "runfile")
				if isFile(try) {
					nextTaskfile = try
					break
				}
			}

			if nextTaskfile != "" {
				tf := schema.NewRunfile()
				err := tf.DecodeYAMLFile(nextTaskfile)
				if err != nil {
					return errors.New("Failed to read runfile: " + nextTaskfile + " " + err.Error())
				}

				for _, k := range wf.Env.Keys() {
					v0 := wf.Env.GetString(k)
					if v, ok := os.LookupEnv(k); !ok || v0 != v {
						os.Setenv(k, v0)
					}
				}

				wf2 := NewWorkflow()
				err = wf2.Load(*tf)

				if err != nil {
					return errors.New("Failed to load runfile: " + nextTaskfile + " " + err.Error())
				}

				wf2.parent = wf
				// app must be empty
				return wf2.RunLifecycle(target, "", contextName)
			}
		}
	}

	if len(targets) == 0 {
		return errors.New("no " + target + " tasks found")
	}

	wf.ContextName = contextName
	return wf.Run(targets, []string{})
}

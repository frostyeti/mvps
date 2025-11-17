package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/workflows"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v4"
)

func getFile(file string, dir string) (string, error) {

	if file == "" && dir == "" {
		wd, _ := os.Getwd()
		if wd != "" {
			file = filepath.Join(wd, "runfile")
			if _, err := os.Stat(file); err == nil {
				return file, nil
			}
		}

		parentDir := filepath.Dir(wd)
		for parentDir != "" && parentDir != "/" && parentDir != "." {
			file = filepath.Join(parentDir, "runfile")
			if _, err := os.Stat(file); err == nil {
				return file, nil
			}
			parentDir = filepath.Dir(parentDir)
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(homeDir, "runfile")
		if _, err := os.Stat(file); err == nil {
			return file, nil
		}
		return "", os.ErrNotExist
	}

	if file != "" {

		file, err := resolvePath(file)
		if err != nil {
			return "", err
		}

		if _, err := os.Stat(file); err == nil {
			return file, nil
		}
	}

	if dir != "" {
		localTaskFile := ""
		cwd, err := os.Getwd()
		if err == nil {
			// fast check
			file = filepath.Join(cwd, dir, "runfile")
			if _, err := os.Stat(file); err == nil {
				return file, nil
			}

			file = filepath.Join(cwd, "runfile")
			if _, err := os.Stat(file); err == nil {
				localTaskFile = file
			}
		}

		if localTaskFile == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			file = filepath.Join(homeDir, "runfile")
			if _, err := os.Stat(file); err == nil {
				localTaskFile = file
			}
		}

		if localTaskFile != "" {
			config := map[string]interface{}{}
			data, err := os.ReadFile(localTaskFile)
			if err != nil {
				return "", fmt.Errorf("error reading runfile: %v", err)
			}

			if err := yaml.Unmarshal(data, &config); err != nil {
				return "", fmt.Errorf("error parsing runfile: %v", err)
			}

			if config["config"] == nil {
				return "", fmt.Errorf("no config section found in runfile")
			}

			configSection, ok := config["config"].(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("config section is not a mapping in runfile")
			}

			dirs := []string{}
			wd, _ := os.Getwd()
			if len(wd) > 0 {
				dirs = append(dirs, wd)
			}

			obj, ok := configSection["delegated-dirs"]
			if !ok {
				return "", fmt.Errorf("delegated-dirs section is not defined in runfile")
			}

			// determine what type of object it is
			switch obj := obj.(type) {
			case string:
				dirs = append(dirs, obj)

			case []interface{}:
				for _, v := range obj {
					if str, ok := v.(string); ok {
						dirs = append(dirs, str)
					}
				}
			}
			if len(dirs) == 0 {
				return "", fmt.Errorf("no directories found in runfile config")
			}

			for _, d := range dirs {
				if !filepath.IsAbs(d) {
					n, err := filepath.Abs(d)
					if err != nil {
						return "", fmt.Errorf("error resolving directory: %v", err)
					}
					d = n
				}
				file = filepath.Join(d, dir, "runfile")
				if _, err := os.Stat(file); err == nil {
					return file, nil
				}
			}

		}
	}

	return "", os.ErrNotExist
}

func resolvePath(file string) (string, error) {
	if file == "" {
		return os.Getwd()
	}

	if len(file) > 2 {
		if file[0] == '~' && (file[1] == '/' || file[1] == '\\') {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(homeDir, file[2:], "runfile"), nil
		} else if file[0] == '.' {
			i := 1
			if file[i] == '.' {
				i++
			}

			i++
			if file[i] == '/' || file[i] == '\\' {
				fp, err := filepath.Abs(file[i:])
				if err != nil {
					return "", err
				}
				return filepath.Join(fp, "runfile"), nil
			}
		}
	}

	uri, _ := url.Parse(file)
	if uri != nil && uri.Scheme == "file://" && uri.Path != "" {
		return filepath.Clean(uri.Path), nil
	}

	if !filepath.IsAbs(file) {
		return filepath.Abs(file)
	}

	return file, nil
}

func runLifecycle(target string, cmd *cobra.Command) error {
	flags := cmd.Flags()

	apps := flags.Args()
	file, _ := flags.GetString("file")
	dir, _ := flags.GetString("dir")

	file, err := getFile(file, dir)
	if err != nil {
		return fmt.Errorf("error finding runfile: %v", err)
	}

	dotenvFiles, _ := flags.GetStringArray("dotenv")
	envVars, _ := flags.GetStringToString("env")
	contextName, _ := flags.GetString("context")
	if contextName == "" {
		contextName = "default"
	}

	rf := schema.NewRunfile()
	err = rf.DecodeYAMLFile(file)
	if err != nil {
		return fmt.Errorf("error loading runfile: %v", err)
	}

	if len(dotenvFiles) > 0 {
		rf.DotEnv = append(rf.DotEnv, dotenvFiles...)
	}

	if len(envVars) > 0 {

		for k, v := range envVars {
			rf.Env.Set(k, v)
		}
	}

	wf := workflows.NewWorkflow()

	err = wf.Load(*rf)
	if err != nil {
		return fmt.Errorf("error loading runfile: %v", err)
	}

	wf.Context = cmd.Context()
	if wf.ContextName == "" {
		wf.ContextName = contextName
	}

	if len(apps) == 0 {
		apps = []string{"default"}
	}

	for _, app := range apps {
		if app != "" {
			err := wf.RunLifecycle(target, app, contextName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

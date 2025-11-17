package workflows

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/run/paths"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/tasks"
	"github.com/frostyeti/mvps/go/run/versions"
	"go.yaml.in/yaml/v4"
)

func (wf *Workflow) Load(runfile schema.Runfile) error {

	wf.Path = runfile.Path
	err := wf.LoadEnv(runfile)
	if err != nil {
		return err
	}
	oldDir, err := os.Getwd()
	if err != nil {
		return err
	}
	defer os.Chdir(oldDir)
	rootDir := filepath.Dir(runfile.Path)
	os.Chdir(rootDir)

	envMap := wf.Env
	if len(runfile.HostImports.Imports) > 0 {
		imports := runfile.HostImports.Imports
		for _, imp := range imports {
			opts := &env.ExpandOptions{
				Get: func(key string) string {
					s, ok := envMap.Get(key)
					if ok {
						return s
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
				CommandSubstitution: runfile.Config.Substitution,
			}
			next, err := env.ExpandWithOptions(imp, opts)
			if err != nil {
				return errors.New("failed to expand hosts import path: " + imp + " error: " + err.Error())
			}

			next = strings.TrimSpace(next)
			optional := false
			if strings.HasSuffix(next, "?") {
				optional = true
				next = strings.TrimSuffix(next, "?")
			}

			if !(filepath.IsAbs(next)) {
				p, err := filepath.Abs(next)
				if err != nil {
					return errors.New("failed to get absolute path of hosts import: " + next + " error: " + err.Error())
				}
				next = p
			}

			if !isFile(next) {
				if optional {
					continue
				} else {
					return errors.New("required hosts import file does not exist: " + next)
				}
			}

			data, err := os.ReadFile(next)
			if err != nil {
				return errors.New("failed to read hosts import file: " + next + " error: " + err.Error())
			}

			var hostfile schema.RunHostsfile
			err = hostfile.Decode(data)
			if err != nil {
				return errors.New("failed to parse hosts import file: " + next + " error: " + err.Error())
			}

			for k, v := range hostfile.Hosts.Entries() {
				wf.Hosts.Set(k, &v)
			}
		}
	}

	if len(runfile.HostImports.Imports) > 0 {
		for k, v := range runfile.HostImports.Hosts.Entries() {
			wf.Hosts.Set(k, &v)
		}
	}

	for _, v := range runfile.Tasks.Entries() {
		wf.Tasks.Set(&v)

		run := ""
		if v.Run != nil && len(*v.Run) > 0 {
			run = *v.Run
		}

		run = strings.TrimSpace(run)

		if len(run) > 0 {

			if !strings.ContainsAny(run, "\n\r") && (strings.HasSuffix(run, ".run.yaml") || strings.HasSuffix(run, ".run.yml")) {
				if strings.Contains(run, "://") {
					uri, err := url.Parse(run)
					if err != nil {
						return errors.New("failed to parse task import URI: " + run + " error: " + err.Error())
					}

					if uri.Scheme != "file" {
						continue
					}

					r := uri.Path
					run = strings.TrimSpace(r)
				}

				opts := &env.ExpandOptions{
					Get: func(key string) string {
						s, ok := envMap.Get(key)
						if ok {
							return s
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
					CommandSubstitution: runfile.Config.Substitution,
				}

				next, err := env.ExpandWithOptions(run, opts)
				run = next
				if err != nil {
					return errors.New("failed to expand task import path: " + run + " error: " + err.Error())
				}

				run = strings.TrimSpace(run)
				if !(filepath.IsAbs(run)) {
					p, err := filepath.Abs(filepath.Join(rootDir, run))
					if err != nil {
						return errors.New("failed to get absolute path of task import: " + run + " error: " + err.Error())
					}
					run = p
				}

				if !isFile(run) {
					return errors.New("task import file does not exist: " + run)
				}

				data, err := os.ReadFile(run)
				if err != nil {
					return errors.New("failed to read task import file: " + run + " error: " + err.Error())
				}

				var task schema.Task
				err = yaml.Unmarshal(data, &task)
				if err != nil {
					return errors.New("failed to parse task import file: " + run + " error: " + err.Error())
				}

				wf.Tasks.Set(&task)
			}
		}
	}

	// continue loadding other parts like Hosts, Tasks, etc.

	return nil
}

func (wf *Workflow) LoadEnv(runfile schema.Runfile) error {

	if len(runfile.Path) == 0 {
		return errors.New("taskfile path is empty")
	}

	if wf.Path == "" {
		wf.Path = runfile.Path
	}

	if !(filepath.IsAbs(runfile.Path)) {
		p, err := filepath.Abs(runfile.Path)
		if err != nil {
			return err
		}
		runfile.Path = p
	}

	rootDir := filepath.Dir(runfile.Path)
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}

	os.Chdir(rootDir)
	defer os.Chdir(currentDir)

	if wf == nil {
		wf = NewWorkflow()
	}

	for _, k := range runfile.Import.Tasks {
		if len(k.Path) == 0 {
			return errors.New("task import path is empty")
		}

		taskDefs := &schema.TaskDefs{
			Path: k.Path,
		}
		err := taskDefs.DecodeYAMLFile(k.Path)
		if err != nil {
			return errors.New("failed to load task import file: " + k.Path + " error: " + err.Error())
		}

		for _, taskDef := range taskDefs.Tasks {
			if taskDef.Id == "" {
				return errors.New("task import file: " + k.Path + " has task with empty id")
			}

			taskDef.Path = k.Path
			tasks.RegisterDynamicTask(taskDef.Id, taskDef)
		}
	}

	envMap := schema.NewEnv()
	for _, n := range os.Environ() {
		parts := strings.SplitN(n, "=", 2)
		if len(parts) == 2 {
			envMap.Set(parts[0], parts[1])
		} else {
			envMap.Set(parts[0], "")
		}
	}

	normalizeEnv(envMap)
	envMap.Set("RUN_FILE", runfile.Path)
	envMap.Set("RUN_DIR", rootDir)
	envMap.Set("RUN_ROOT_DIR", rootDir)
	envMap.Set("RUN_ROOT_FILE", runfile.Path)
	if wf.parent != nil {
		wf0 := wf.parent
		if wf0.Path != "" {
			envMap.Set("RUN_ROOT_FILE", wf0.Path)
			envMap.Set("RUN_ROOT_DIR", filepath.Dir(wf0.Path))
		}
	}

	if wf.ContextName == "" && env.Has("RUN_CONTEXT") {
		wf.ContextName = env.Get("RUN_CONTEXT")
	}

	defaultShell := "shell"
	if runfile.Config.Shell != nil && len(*runfile.Config.Shell) > 0 {
		defaultShell = *runfile.Config.Shell
	}

	envMap.Set("RUN_CONTEXT", wf.ContextName)
	envMap.Set("RUN_SHELL", defaultShell)

	if wf.Config.Dirs.Scripts == "" {
		wf.Config.Dirs.Scripts = "./.run/scripts"
	}

	envMap.Set("RUN_ETC_DIR", wf.Config.Dirs.Etc)
	configHome := envMap.GetString("RUN_CONFIG_HOME")
	if configHome == "" {
		configHome, _ = paths.UserConfigDir()
	}
	envMap.Set("RUN_CONFIG_HOME", configHome)
	dataHome := envMap.GetString("RUN_DATA_HOME")
	if dataHome == "" {
		dataHome, _ = paths.UserDataDir()
	}
	envMap.Set("RUN_DATA_HOME", dataHome)
	cacheHome := envMap.GetString("RUN_CACHE_HOME")
	if cacheHome == "" {
		cacheHome, _ = paths.UserCacheDir()
	}
	envMap.Set("RUN_CACHE_HOME", cacheHome)
	stateHome := envMap.GetString("RUN_STATE_HOME")
	if stateHome == "" {
		stateHome, _ = paths.UserStateDir()
	}
	envMap.Set("RUN_STATE_HOME", stateHome)
	envMap.Set("RUN_PROJECTS_DIRS", strings.Join(wf.Config.Dirs.Projects, string(os.PathListSeparator)))
	envMap.Set("RUN_VERSION", versions.VERSION) // TODO: set actual version

	if envMap.Has("SUDO_USER") && runtime.GOOS != "windows" {
		u, err := user.Lookup(env.Get("SUDO_USER"))
		if err == nil {
			binDir := fmt.Sprintf("%s/.local/bin", u.HomeDir)
			envMap.PrependPath(binDir)
		}
	}

	envMap.PrependPath("./node_modules/.bin")
	envMap.PrependPath("./bin")

	if _, ok := envMap.Get("RUN_ENV"); !ok {
		f, err := os.CreateTemp("", "run-env-")
		if err != nil {
			return err
		}
		f.Write([]byte{})
		f.Close()
		envMap.Set("RUN_ENV", f.Name())
		wf.cleanupEnv = true
	}

	if _, ok := envMap.Get("RUN_PATH"); !ok {
		f, err := os.CreateTemp("", "run-path-")
		if err != nil {
			return err
		}
		f.Write([]byte{})
		f.Close()

		envMap.Set("RUN_PATH", f.Name())
		wf.cleanupPath = true
	}

	if len(runfile.Config.Paths) > 0 {
		for _, p := range runfile.Config.Paths {
			if p.OS != "" {
				if !strings.EqualFold(p.OS, runtime.GOOS) {
					continue
				}
			}

			opts := &env.ExpandOptions{
				Get: func(key string) string {
					s, ok := envMap.Get(key)
					if ok {
						return s
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
				CommandSubstitution: runfile.Config.Substitution,
			}
			path, err := env.ExpandWithOptions(p.Path, opts)
			if err != nil {
				return errors.New("failed to expand prepend-path: " + p.Path + " error: " + err.Error())
			}
			path = strings.TrimSpace(path)
			if !(filepath.IsAbs(path)) {
				abs, err := filepath.Abs(filepath.Join(rootDir, path))
				if err != nil {
					return errors.New("failed to get absolute path of prepend-path: " + path + " error: " + err.Error())
				}
				path = abs
			}

			env.PrependPath(path)
		}
	}

	dotenvFiles := []string{}
	if wf.Config.Dirs.Etc == "" {
		wf.Config.Dirs.Etc = "./.run/etc"
	}

	if len(wf.Config.Dirs.Projects) == 0 {
		wf.Config.Dirs.Projects = []string{"./.run/apps/*"}
		data := envMap.GetString("RUN_DATA_HOME")
		if len(data) > 0 {
			wf.Config.Dirs.Projects = append(wf.Config.Dirs.Projects, data+"/apps/*")
		}
	}

	if isDir(configHome) {
		dotenvFiles = append(dotenvFiles, filepath.Join(configHome, ".env?"))
		if wf.ContextName == "default" || wf.ContextName == "" {
			dotenvFiles = append(dotenvFiles, filepath.Join(configHome, ".env.default?"))
		} else {
			dotenvFiles = append(dotenvFiles, filepath.Join(configHome, ".env."+wf.ContextName+"?"))
		}
	}

	if isDir(wf.Config.Dirs.Etc) {
		dotenvFiles = append(dotenvFiles, filepath.Join(wf.Config.Dirs.Etc, ".env?"))
		if wf.ContextName == "default" || wf.ContextName == "" {
			dotenvFiles = append(dotenvFiles, filepath.Join(wf.Config.Dirs.Etc, ".env.default?"))
		} else {
			dotenvFiles = append(dotenvFiles, filepath.Join(wf.Config.Dirs.Etc, ".env."+wf.ContextName+"?"))
		}
	}

	if wf.ContextName == "default" || wf.ContextName == "" {
		dotenvFiles = append(dotenvFiles, filepath.Join(rootDir, ".env?"))
		dotenvFiles = append(dotenvFiles, filepath.Join(rootDir, ".env.default?"))
	} else {
		dotenvFiles = append(dotenvFiles, filepath.Join(rootDir, ".env."+wf.ContextName+"?"))
	}

	if len(runfile.DotEnv) > 0 {
		for _, f := range runfile.DotEnv {
			skip := false
			for _, existing := range dotenvFiles {
				if existing == f {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			dotenvFiles = append(dotenvFiles, f)
		}
	}

	if runfile.Config.Env.Len() > 0 {
		opts := &env.ExpandOptions{
			Get: func(key string) string {
				s, ok := envMap.Get(key)
				if ok {
					return s
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
			CommandSubstitution: runfile.Config.Substitution,
		}

		for k, v := range runfile.Config.Env.Iter() {
			expandedValue, err := env.ExpandWithOptions(v, opts)
			if err != nil {
				return err
			}
			envMap.Set(k, expandedValue)

			hasKey := false
			for _, key := range opts.Keys {
				if key == k {
					hasKey = true
					break
				}
			}
			if !hasKey {
				opts.Keys = append(opts.Keys, k)
			}
		}
	}

	if len(dotenvFiles) > 0 {
		opts := &env.ExpandOptions{
			Get: func(key string) string {
				s, ok := envMap.Get(key)
				if ok {
					return s
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
			CommandSubstitution: runfile.Config.Substitution,
		}

		globalDoc := dotenv.NewDocument()

		for _, f := range dotenvFiles {
			next, err := env.ExpandWithOptions(f, opts)
			if err != nil {
				return errors.New("failed to expand dotenv file path: " + f + " error: " + err.Error())
			}

			optional := false
			if strings.HasSuffix(next, "?") {
				optional = true
				next = strings.TrimSuffix(next, "?")
			}

			if !(filepath.IsAbs(next)) {
				abs, err := filepath.Abs(next)
				if err != nil {
					return errors.New("failed to get absolute path of dotenv file: " + next + " error: " + err.Error())
				}
				next = abs
			}

			if !isFile(next) {
				if optional {
					continue
				} else {
					return errors.New("required dotenv file does not exist: " + next)
				}
			}

			data, err := os.ReadFile(next)
			if err != nil {
				return errors.New("failed to read dotenv file: " + next + " error: " + err.Error())
			}

			doc, err := dotenv.Parse(string(data))
			if err != nil {
				return errors.New("failed to parse dotenv file: " + next + " error: " + err.Error())
			}

			globalDoc.Merge(doc)
		}

		for _, node := range globalDoc.ToArray() {
			if node.Type != dotenv.VARIABLE_TOKEN {
				continue
			}

			keyPtr := node.Key
			if keyPtr == nil {
				continue
			}

			key := *keyPtr
			value := node.Value
			expandedValue, err := env.ExpandWithOptions(value, opts)
			if err != nil {
				return errors.New("failed to expand dotenv variable: " + key + " error: " + err.Error())
			}
			envMap.Set(key, expandedValue)

			hasKey := false
			for _, k := range opts.Keys {
				if k == key {
					hasKey = true
					break
				}
			}
			if !hasKey {
				opts.Keys = append(opts.Keys, key)
			}
		}
	}

	if runfile.Env.Len() > 0 {
		opts := &env.ExpandOptions{
			Get: func(key string) string {
				s, ok := envMap.Get(key)
				if ok {
					return s
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
			CommandSubstitution: runfile.Config.Substitution,
		}
		for k, v := range runfile.Env.Iter() {
			expandedValue, err := env.ExpandWithOptions(v, opts)
			if err != nil {
				return err
			}
			envMap.Set(k, expandedValue)

			hasKey := false
			for _, key := range opts.Keys {
				if key == k {
					hasKey = true
					break
				}
			}
			if !hasKey {
				opts.Keys = append(opts.Keys, k)
			}
		}
	}

	wf.Env = envMap

	return nil
}

func normalizeEnv(envMap *schema.Environment) error {

	configHome := os.Getenv("XDG_CONFIG_HOME")
	dataHome := os.Getenv("XDG_DATA_HOME")
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	stateHome := os.Getenv("XDG_STATE_HOME")
	binHome := os.Getenv("XDG_BIN_HOME")
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	envMap.Set("OS_PLATFORM", runtime.GOOS)
	envMap.Set("OS_ARCH", runtime.GOARCH)

	if runtime.GOOS == "windows" {
		envMap.Set("OSTYPE", "windows")
		user, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		shell, ok := os.LookupEnv("SHELL")
		if !ok {
			shell = "powershell.exe"
		}
		envMap.Set("HOME", user)
		envMap.Set("HOMEPATH", user)
		envMap.Set("USER", user)
		envMap.Set("HOSTNAME", host)
		envMap.Set("SHELL", shell)

		if len(configHome) == 0 {
			configHome = filepath.Join(user, "AppData", "Roaming")
			envMap.Set("XDG_CONFIG_HOME", configHome)
		}

		if len(dataHome) == 0 {
			dataHome = filepath.Join(user, "AppData", "Local")
			envMap.Set("XDG_DATA_HOME", dataHome)
		}

		if len(cacheHome) == 0 {
			cacheHome = filepath.Join(user, "AppData", "Local", "Cache")
			envMap.Set("XDG_CACHE_HOME", cacheHome)
		}

		if len(stateHome) == 0 {
			stateHome = filepath.Join(user, "AppData", "Local", "State")
			envMap.Set("XDG_STATE_HOME", stateHome)
		}

		if len(binHome) == 0 {
			binHome = filepath.Join(user, "AppData", "Local", "Programs", "bin")
			envMap.Set("XDG_BIN_HOME", binHome)
		}

		if len(runtimeDir) == 0 {
			runtimeDir = filepath.Join(user, "AppData", "Local", "Temp")
			envMap.Set("XDG_RUNTIME_DIR", runtimeDir)
		}
	} else {
		osType := os.Getenv("OSTYPE")
		if len(osType) == 0 {
			osType = runtime.GOOS
			envMap.Set("OSTYPE", osType)
		}

		user, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		if len(configHome) == 0 {
			configHome = filepath.Join(user, ".config")
			envMap.Set("XDG_CONFIG_HOME", configHome)
		}

		if len(dataHome) == 0 {
			dataHome = filepath.Join(user, ".local", "share")
			envMap.Set("XDG_DATA_HOME", dataHome)
		}

		if len(cacheHome) == 0 {
			cacheHome = filepath.Join(user, ".cache")
			envMap.Set("XDG_CACHE_HOME", cacheHome)
		}

		if len(stateHome) == 0 {
			stateHome = filepath.Join(user, ".local", "state")
			envMap.Set("XDG_STATE_HOME", stateHome)
		}

		if len(binHome) == 0 {
			binHome = filepath.Join(user, ".local", "bin")
			envMap.Set("XDG_BIN_HOME", binHome)
		}

		if len(runtimeDir) == 0 {
			id := os.Getuid()
			runtimeDir = filepath.Join("user", "run", fmt.Sprintf("%d", id))
			envMap.Set("XDG_RUNTIME_DIR", runtimeDir)
		}
	}

	return nil
}

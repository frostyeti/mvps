/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/frostyeti/mvps/go/dotenv"
	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/frostyeti/mvps/go/rtexec/powershell"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:     "file",
	Aliases: []string{"f"},
	Short:   "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runFile(cmd, args)
	},
}

func runFile(cmd *cobra.Command, args []string) {
	// run file -e ENV=val -E envfile -w <working_dir> <file> <args...>
	file := ""
	envMap := schema.NewEnv()
	for k, v := range env.All() {
		envMap.Set(k, v)
	}

	inRemainingArgs := false
	remaining := []string{}

	env.PrependPath("./node_modules/.bin")
	env.PrependPath("./bin")

	workingDir, err := os.Getwd()
	if err != nil {
		cmd.PrintErrf("Error getting working directory: %v\n", err)
		os.Exit(1)
	}
	for i := 0; i < len(args); i++ {
		next := args[i]
		if inRemainingArgs {
			remaining = append(remaining, next)
			continue
		}

		if strings.ContainsRune(next, '=') {
			parts := strings.SplitN(next, "=", 2)
			key := parts[0]
			value := parts[1]
			envMap.Set(key, value)
			continue
		}

		switch next {
		case "-w", "--cwd", "--pwd":
			workingDir = next
			continue
		case "-e", "--env":
			if i+1 < len(args) {
				i++
				parts := strings.SplitN(args[i], "=", 2)
				key := parts[0]
				value := parts[1]
				envMap.Set(key, value)
				continue
			}
		case "-E", "--dotenv", "--envfile":
			if i+1 < len(args) {
				i++
				dotenvFile := args[i]
				required := !strings.HasSuffix(dotenvFile, "?")

				if _, err := os.Stat(dotenvFile); os.IsNotExist(err) && required {
					cmd.PrintErrf("Dotenv file %s not found and is required\n", dotenvFile)
					os.Exit(1)
				}

				fileBytes, err := os.ReadFile(dotenvFile)
				if err != nil {
					cmd.PrintErrf("Error reading dotenv file %s: %v\n", dotenvFile, err)
					os.Exit(1)
				}

				content := string(fileBytes)

				doc, err := dotenv.Parse(content)
				if err != nil {
					cmd.PrintErrf("Error parsing dotenv file %s: %v\n", dotenvFile, err)
					os.Exit(1)
				}

				expandOptions := &env.ExpandOptions{
					Get: func(name string) string {
						v, ok := envMap.Get(name)
						if ok {
							return v
						}

						v, ok = os.LookupEnv(name)
						if ok {
							return v
						}

						return ""
					},
					Set: func(name, value string) error {
						envMap.Set(name, value)

						return nil
					},
				}

				for _, node := range doc.ToArray() {
					if node.Type == dotenv.VARIABLE_TOKEN {
						k := node.Key
						value := node.Value
						if k == nil {
							continue
						}

						key := *k

						resolvedValue, err := env.ExpandWithOptions(value, expandOptions)

						if err != nil {
							cmd.PrintErrf("Error expanding variable %s in dotenv file %s: %v\n", key, dotenvFile, err)
							os.Exit(1)
						}
						envMap.Set(key, resolvedValue)
						continue
					}
				}

				continue
			}
		}

		inRemainingArgs = true
		file = next
	}

	ext := filepath.Ext(file)
	switch ext {
	case ".go":
		nextArgs := []string{}
		nextArgs = append(nextArgs, "run")
		nextArgs = append(nextArgs, file)
		if len(remaining) > 0 {
			nextArgs = append(nextArgs, remaining...)
		}
		goCmd := exec.New("go", nextArgs...)
		goCmd.WithEnvMap(envMap.ToMap())
		goCmd.WithCwd(workingDir)
		res, err := goCmd.Run()
		if err != nil {
			cmd.PrintErrf("Error executing go file %s: %v\n", file, err)
			os.Exit(1)
		}
		os.Exit(res.Code)

	case ".cs":
		// dotnet 10+ supports `dotnet run <file.cs>` directly
		nextArgs := []string{}
		nextArgs = append(nextArgs, "run")
		nextArgs = append(nextArgs, file)
		if len(remaining) > 0 {
			nextArgs = append(nextArgs, remaining...)
		}
		csCmd := exec.New("dotnet", nextArgs...)
		csCmd.WithEnvMap(envMap.ToMap())
		csCmd.WithCwd(workingDir)
		res, err := csCmd.Run()
		if err != nil {
			cmd.PrintErrf("Error executing csharp file %s: %v\n", file, err)
			os.Exit(1)
		}
		os.Exit(res.Code)
	case ".csproj", ".fsproj", ".vbproj":
		// dotnet run works with project files directly
		nextArgs := []string{}
		nextArgs = append(nextArgs, "run")
		nextArgs = append(nextArgs, "--project")
		nextArgs = append(nextArgs, file)
		if len(remaining) > 0 {
			nextArgs = append(nextArgs, "--")
			nextArgs = append(nextArgs, remaining...)
		}

		csCmd := exec.New("dotnet", nextArgs...)
		csCmd.WithEnvMap(envMap.ToMap())
		csCmd.WithCwd(workingDir)
		res, err := csCmd.Run()
		if err != nil {
			cmd.PrintErrf("Error executing dotnet project file %s: %v\n", file, err)
			os.Exit(1)
		}
		os.Exit(res.Code)

	case ".java":
		javacPath, ok := exec.Which("javac")
		if !ok {
			cmd.PrintErrf("javac not found in PATH")
			os.Exit(1)
		}

		javacCmd := exec.New(javacPath, file)
		javacCmd.WithEnvMap(envMap.ToMap())
		javacCmd.WithCwd(workingDir)
		res, err := javacCmd.Run()
		if err != nil || res.Code != 0 {
			cmd.PrintErrf("Error compiling java file %s: %v\n", file, err)
			os.Exit(1)
		}

		className := strings.TrimSuffix(filepath.Base(file), ".java")
		javaCmd := exec.New("java", className)
		if len(remaining) > 0 {
			javaArgs := javaCmd.Args
			javaArgs = append(javaArgs, remaining...)
			javaCmd.Args = javaArgs
		}
		javaCmd.WithEnvMap(envMap.ToMap())
		javaCmd.WithCwd(workingDir)
		res, err = javaCmd.Run()
		if err != nil {
			cmd.PrintErrf("Error executing java file %s: %v\n", file, err)
			os.Exit(1)
		}
		os.Exit(res.Code)

	}

	if runtime.GOOS == "windows" {

		// short-circuit if it's an exe, com, bat, cmd, etc.
		pathext := env.Get("PATHEXT")
		if pathext == "" {
			// change to lower
			pathext = ".com;.exe;.bat;.cmd;.vbs;.vbe;.js;.jse;.wsf;.wsh;.msc"
		} else {
			pathext = strings.ToLower(pathext)
		}

		extensions := strings.Split(pathext, ";")

		if ext == "" {
			found := false
			for _, ext := range extensions {
				tryFile := file + ext
				if _, err := os.Stat(tryFile); err == nil {
					file = tryFile
					found = true
					break
				}
			}

			if found {
				ext = filepath.Ext(file)
			}
		}

		if _, err := os.Stat(file); os.IsNotExist(err) {
			cmd.PrintErrf("File %s not found\n", file)
			os.Exit(1)
		}

		if ext != "" {
			knownExec := false
			for _, nextExt := range extensions {
				if strings.EqualFold(ext, nextExt) {
					knownExec = true
					break
				}
			}

			if knownExec {
				cmd0 := exec.New(file, remaining...)
				cmd0.WithEnvMap(envMap.ToMap())
				cmd0.WithCwd(workingDir)
				res, err := cmd0.Run()
				if err != nil {
					cmd.PrintErrf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)
			}
		}

		file, err := filepath.Abs(file)
		if err != nil {
			fmt.Printf("Error resolving file path %s: %v\n", file, err)
			os.Exit(1)
		}

		// read the first line only
		fileHandle, err := os.Open(file)
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", file, err)
			os.Exit(1)
		}

		// see if file has shebang

		// Create a scanner to read line by line
		scanner := bufio.NewScanner(fileHandle)
		shebang := ""

		if scanner.Scan() {
			firstLine := scanner.Text()
			if strings.HasPrefix(firstLine, "#!") {
				shebang = firstLine
			}

			if err := scanner.Err(); err != nil {
				fileHandle.Close()
				fmt.Printf("Error reading file %s: %v\n", file, err)
				os.Exit(1)
			}
			fileHandle.Close()
		}

		shebang = strings.TrimSpace(shebang)
		if len(shebang) > 0 {
			shebang = shebang[2:]
			parts := strings.Fields(shebang)

			// handle the use case of env on windows e.g. #!/usr/bin/env bash
			if strings.HasSuffix(parts[0], "/env") {
				// get env path on windows
				// pass off to env command
				resolvedPath, ok := exec.Which("env")
				nextArgs := parts[1:]
				// if env is on the windows environment PATH, we can use it
				// directly and just pass off the rest of the args to it.
				if ok {
					cmd := exec.New(resolvedPath, nextArgs...)
					cmd.WithEnvMap(envMap.ToMap())
					cmd.WithCwd(workingDir)
					res, err := cmd.Run()
					if err != nil {
						fmt.Printf("Error executing shebang command: %v\n", err)
						os.Exit(1)
					}
					os.Exit(res.Code)

				} else {

					// else, we need to provide a good faith effort to handle env ourselves
					if len(parts) <= 1 {
						fmt.Printf("calling env in shebang requires more than one argument\n")
						os.Exit(1)
					}

					// handle split-string option
					if parts[1] == "-S" {
						// handle -S option
						nextArgs := []string{}
						inRemainingArgs := false
						exeName := ""
						for j := 2; j < len(parts); j++ {
							next := parts[j]
							if inRemainingArgs {
								nextArgs = append(nextArgs, next)
								continue
							}

							if strings.ContainsRune(next, '=') {
								envParts := strings.SplitN(next, "=", 2)
								key := envParts[0]
								value := envParts[1]
								envMap.Set(key, value)
								continue
							}

							exeName = next
							inRemainingArgs = true
						}

						if exeName == "" {
							fmt.Printf("No executable specified in shebang %s \n", shebang)
							os.Exit(1)
						}

						exePath, ok := exec.Which(exeName)
						if !ok {
							fmt.Printf("Shebang executable %s not found in PATH\n", exeName)
							os.Exit(1)
						}
						exeName = exePath

						nextArgs = append(nextArgs, file)
						cmd := exec.New(exeName, nextArgs...)
						cmd.WithEnvMap(envMap.ToMap())
						cmd.WithCwd(workingDir)
						res, err := cmd.Run()
						if err != nil {
							fmt.Printf("Error executing shebang command: %v\n", err)
							os.Exit(1)
						}
						os.Exit(res.Code)
					} else {
						exeName := parts[1]
						if exeName == "" {
							fmt.Printf("No executable specified in shebang %s \n", shebang)
							os.Exit(1)
						}

						exePath, ok := exec.Which(exeName)
						if !ok {
							fmt.Printf("Shebang executable %s not found in PATH\n", exeName)
							os.Exit(1)
						}
						exeName = exePath
						nextArgs := []string{file}
						cmd := exec.New(exeName, nextArgs...)
						cmd.WithEnvMap(envMap.ToMap())
						cmd.WithCwd(workingDir)
						res, err := cmd.Run()
						if err != nil {
							fmt.Printf("Error executing shebang command: %v\n", err)
							os.Exit(1)
						}
						os.Exit(res.Code)
					}
				}

			} else {
				// since this is windows, we need to get name of the executable and find it in
				// environment PATH since shebang may have a unix-style path.
				exeName := filepath.Base(parts[0])
				exePath, ok := exec.Which(exeName)
				if !ok {
					fmt.Printf("Shebang executable %s not found in PATH\n", exeName)
					os.Exit(1)
				}
				exeName = exePath
				nextArgs := parts[1:]
				nextArgs = append(nextArgs, file)
				cmd := exec.New(exeName, nextArgs...)
				cmd.WithEnvMap(envMap.ToMap())
				cmd.WithCwd(workingDir)
				res, err := cmd.Run()
				if err != nil {
					fmt.Printf("Error executing shebang command: %v\n", err)
					os.Exit(1)
				}
				os.Exit(res.Code)
			}
		} else {
			// attempt to handle well known script types based on extension

			switch ext {
			case ".ps1":
				pwshCmd := powershell.Script(file)
				pwshArgs := pwshCmd.Args
				if len(remaining) > 0 {
					pwshArgs = append(pwshArgs, remaining...)
					pwshCmd.Args = pwshArgs
				}

				pwshCmd.WithEnvMap(envMap.ToMap())
				pwshCmd.WithCwd(workingDir)
				res, err := pwshCmd.Run()
				if err != nil {
					fmt.Printf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)
			case ".rb":
				rubyCmd := exec.New("ruby", file)
				if len(remaining) > 0 {
					rubyArgs := rubyCmd.Args
					rubyArgs = append(rubyArgs, remaining...)
					rubyCmd.Args = rubyArgs
				}
				rubyCmd.WithEnvMap(envMap.ToMap())
				rubyCmd.WithCwd(workingDir)
				res, err := rubyCmd.Run()
				if err != nil {
					fmt.Printf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)
			case ".py":
				pythonCmd := exec.New("python", file)
				if len(remaining) > 0 {
					pythonArgs := pythonCmd.Args
					pythonArgs = append(pythonArgs, remaining...)
					pythonCmd.Args = pythonArgs
				}
				pythonCmd.WithEnvMap(envMap.ToMap())
				pythonCmd.WithCwd(workingDir)
				res, err := pythonCmd.Run()
				if err != nil {
					fmt.Printf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)

			case ".sh":
				bashCmd := exec.New("bash", file)
				if len(remaining) > 0 {
					bashArgs := bashCmd.Args
					bashArgs = append(bashArgs, remaining...)
					bashCmd.Args = bashArgs
				}
				bashCmd.WithEnvMap(envMap.ToMap())
				bashCmd.WithCwd(workingDir)
				res, err := bashCmd.Run()
				if err != nil {
					fmt.Printf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)

			case ".php":
				phpCmd := exec.New("php", file)
				if len(remaining) > 0 {
					phpArgs := phpCmd.Args
					phpArgs = append(phpArgs, remaining...)
					phpCmd.Args = phpArgs
				}
				phpCmd.WithEnvMap(envMap.ToMap())
				phpCmd.WithCwd(workingDir)
				res, err := phpCmd.Run()
				if err != nil {
					cmd.PrintErrf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)

			case ".js", ".ts":
				nodeCmd := exec.New("node", file)
				if len(remaining) > 0 {
					nodeArgs := nodeCmd.Args
					nodeArgs = append(nodeArgs, remaining...)
					nodeCmd.Args = nodeArgs
				}
				nodeCmd.WithEnvMap(envMap.ToMap())
				nodeCmd.WithCwd(workingDir)
				res, err := nodeCmd.Run()
				if err != nil {
					fmt.Printf("Error executing file %s: %v\n", file, err)
					os.Exit(1)
				}
				os.Exit(res.Code)
			default:
				cmd.PrintErrf("Cannot execute file %s: unknown file type\n", file)
				os.Exit(1)
			}
		}
	} else {
		cmd0 := exec.New(file, remaining...)
		cmd0.WithEnvMap(envMap.ToMap())
		cmd0.WithCwd(workingDir)
		res, err := cmd0.Run()
		if err != nil {
			cmd.PrintErrf("Error executing file %s: %v\n", file, err)
			os.Exit(1)
		}
		os.Exit(res.Code)
	}
}

func init() {
	rootCmd.AddCommand(fileCmd)
	fileCmd.Flags()

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// fileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

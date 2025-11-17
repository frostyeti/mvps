/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/workflows"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// taskCmd represents the run command
var taskCmd = &cobra.Command{
	Use:   "task [OPTIONS] [TASK...] [--] [REMAINING_ARGS...]",
	Short: "Runs a single task from the runfile and may pass remaining arguments to it.",
	Long: `Run a single task from the runfile.
Additional arguments may be passed to the task. The -- separator is may be used to 
force all subsequent arguments to be treated as remaining arguments.`,
	Example: `run task test
  run task -c CONTEXTA -e MY_VAR=test build -- --no-cache
  run task -e ENV=production deploy --tag v1.0.0`,
	Aliases:            []string{"r"},
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, a []string) {

		args := os.Args

		if len(args) > 0 {
			// always will be the cli command
			args = args[1:]

			if len(args) > 0 && args[0] == "task" {
				args = args[1:]
			} else if len(args) > 0 {
				index := -1
				for i, arg := range args {
					if arg == "task" {
						index = i
						break
					}
				}

				if index != -1 {
					args = append(args[:index], args[index+1:]...)
				}
			}
		}

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		flags.StringP("file", "f", env.Get("RUN_FILE"), "Path to the runfile (default is ./runfile)")
		flags.StringP("dir", "d", env.Get("RUN_DIR"), "Directory to run the task in (default is current directory)")
		flags.StringArrayP("dotenv", "E", []string{}, "List of dotenv files to load")
		flags.StringToStringP("env", "e", map[string]string{}, "List of environment variables to set")
		flags.StringP("context", "c", env.Get("RUN_CONTEXT"), "Context to use.")

		targets := []string{}
		cmdArgs := []string{}
		remainingArgs := []string{}
		size := len(args)
		inRemaining := false
		for i := 0; i < size; i++ {
			n := args[i]
			if n == "--" {
				inRemaining = true
				continue
			}

			if inRemaining {
				remainingArgs = append(remainingArgs, args[i])
				continue
			}

			if len(n) > 0 && n[0] == '-' {
				cmdArgs = append(cmdArgs, n)
				j := i + 1
				if j < size && len(args[j]) > 0 && args[j][0] != '-' {
					cmdArgs = append(cmdArgs, args[j])
					i++ // Skip the next argument as it's a value for the flag
				}

				continue
			}

			targets = append(targets, n)
			inRemaining = true
		}

		if len(targets) == 0 {
			targets = append(targets, "default")
		}

		err := flags.Parse(cmdArgs)
		if err != nil {
			cmd.PrintErrf("Error parsing flags: %v\n", err)
			os.Exit(1)
		}

		file, _ := flags.GetString("file")
		dir, _ := flags.GetString("dir")

		file, err = getFile(file, dir)
		if err != nil {
			cmd.PrintErrf("Error resolving file: %v\n", err)
			os.Exit(1)
		}

		dotenvFiles, _ := flags.GetStringArray("dotenv")
		envVars, _ := flags.GetStringToString("env")

		tf := schema.NewRunfile()

		err = tf.DecodeYAMLFile(file)
		tf.Path = file

		if err != nil {
			cmd.PrintErrf("Error loading runfile: %v\n", err)
			os.Exit(1)
		}

		if len(dotenvFiles) > 0 {
			tf.DotEnv = append(tf.DotEnv, dotenvFiles...)
		}

		if len(envVars) > 0 {

			for k, v := range envVars {
				tf.Env.Set(k, v)
			}
		}

		wf := workflows.NewWorkflow()

		err = wf.Load(*tf)
		if err != nil {
			cmd.PrintErrf("Error loading runfile: %v\n", err)
			os.Exit(1)
		}

		err = wf.Run(targets, remainingArgs)

		if err != nil {
			msg := fmt.Errorf("error running workflow: %w", err)
			cmd.PrintErrf("%v\n", msg)
			os.Exit(1)
		}

		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(taskCmd)

	taskCmd.Flags().StringArrayP("dotenv", "E", []string{}, "List of dotenv files to load")
	taskCmd.Flags().StringToStringP("env", "e", map[string]string{}, "List of environment variables to  ")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

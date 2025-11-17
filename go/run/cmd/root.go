/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/frostyeti/mvps/go/env"
	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/versions"
	"github.com/frostyeti/mvps/go/run/workflows"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "run",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Version: versions.VERSION,
	Args:    cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, a []string) error {
		args := os.Args
		// cliName := args[0]
		if len(args) > 0 {
			// always will be the cli command
			args = args[1:]
		}

		if len(args) > 0 {
			firstTarget := ""

			for i := 0; i < len(args); i++ {
				next := args[i]
				if strings.ContainsRune(next, '=') {
					// env var, skip
					continue
				}

				switch next {
				case "-e", "--env", "-E", "--dotenv", "--envfile":
					if i+1 < len(args) {
						i++ // skip next
						continue
					}
				}

				firstTarget = next
				break
			}

			if strings.ContainsAny(firstTarget, "\\/") {
				// handle file, including if file has a shebang
				// call function to handle this
				runFile(cmd, a)
			}

			// if file exists, handle as file
			if fileInfo, err := os.Stat(firstTarget); err == nil && !fileInfo.IsDir() {
				// handle as file
				runFile(cmd, a)
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

		foundOneTarget := false
		for _, t := range targets {
			_, ok := wf.Tasks.Get(t)
			if ok {
				foundOneTarget = true
				break
			}
		}

		if !foundOneTarget {
			msg := fmt.Errorf("no tasks found for targets: %v", targets)
			cmd.PrintErrf("%v\n", msg)
			os.Exit(1)
		}

		err = wf.Run(targets, remainingArgs)

		if err != nil {
			msg := fmt.Errorf("error running workflow: %w", err)
			cmd.PrintErrf("%v\n", msg)
			os.Exit(1)
		}

		os.Exit(0)

		return nil
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	file := env.Get("RUN_FILE")
	dir := env.Get("RUN_DIR")
	context := env.Get("RUN_CONTEXT")

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.task.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().StringP("file", "f", file, "Path to the YAML file.")
	rootCmd.PersistentFlags().StringP("dir", "d", dir, "Directory to run the task in (default is current directory).")
	rootCmd.PersistentFlags().StringP("context", "c", context, "The context to use. If not set, the 'default' context is used.")

}

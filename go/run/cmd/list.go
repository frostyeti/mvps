/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"slices"
	"strings"

	"github.com/frostyeti/mvps/go/run/schema"
	"github.com/frostyeti/mvps/go/run/workflows"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all available tasks",
	Long:    `Lists all available tasks in the runfile.`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		dir, _ := cmd.Flags().GetString("dir")
		file, err := getFile(file, dir)
		if err != nil {
			cmd.PrintErrf("Error loading xtaskfile: %v\n", err)
			os.Exit(1)
		}

		rf := schema.NewRunfile()
		err = rf.DecodeYAMLFile(file)
		if err != nil {
			cmd.PrintErrf("Error decoding xtaskfile: %v\n", err)
			os.Exit(1)
		}

		wf := workflows.NewWorkflow()
		wf.Args = args
		wf.Context = cmd.Context()

		err = wf.Load(*rf)
		if err != nil {
			cmd.PrintErrf("Error loading xtaskfile: %v\n", err)
			os.Exit(1)
		}

		tasks := wf.List()

		names := []string{}
		for _, task := range tasks {
			if task.Name != nil && len(*task.Name) > 0 {
				names = append(names, *task.Name)
			} else {
				names = append(names, task.Id)
			}
		}
		slices.Sort(names)

		longest := 0
		for _, name := range names {
			if len(name) > longest {
				longest = len(name)
			}
		}
		max := longest + 2

		for _, name := range names {
			desc := ""
			for _, task := range tasks {
				if (task.Name != nil && *task.Name == name) || (task.Name == nil && task.Id == name) {
					if task.Desc != nil && len(*task.Desc) > 0 {
						desc = *task.Desc
					}
					break
				}
			}

			pad := max - len(name)
			if pad < 0 {
				pad = 0
			}

			cmd.Println("\x1b[34m" + name + "\x1b[0m" + strings.Repeat(" ", pad) + "  " + desc)
		}
		os.Exit(0)

	},
}

func init() {
	taskCmd.AddCommand(listCmd)
}

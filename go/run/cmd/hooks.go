/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// hooksCmd represents the hooks command
var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, a []string) {
		args := os.Args[1:]
		target := ""

		index := -1
		for i, arg := range args {
			if arg == "runlc" {
				index = i
				break
			}
		}

		if index != -1 {
			if index+1 >= len(args) {
				fmt.Println("Error: target is required")
				os.Exit(1)
			}

			target = args[index+1]
		}

		err := runLifecycle(target, cmd)
		if err != nil {
			cmd.PrintErrf("Error: %v\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	},
}

func init() {
	flags := hooksCmd.Flags()
	flags.StringArrayP("dotenv", "E", []string{}, "List of dotenv files to load")
	flags.StringToStringP("env", "e", map[string]string{}, "List of environment variables to set")
	rootCmd.AddCommand(hooksCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// hooksCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// hooksCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

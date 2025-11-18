package cmd

import (
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit a secret in the secrets database",
	Long:  `Edit a secret in the secrets database using its URI.`,
	Run: func(cmd *cobra.Command, args []string) {

		vault, _ := cmd.Flags().GetString("vault")
		useCode, _ := cmd.Flags().GetBool("use-code")
		if useCode {
			os.Setenv("SOPS_EDITOR", "code --wait --new-window --disable-workspace-trust --disable-extensions --disable-telemetry")
		}

		uriString := vault
		filePath, err := getFilePath(uriString)
		if err != nil {
			color.Red("[ERROR]: Error getting file path: %v", err)
			os.Exit(1)
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			color.Red("[ERROR]: The specified vault file does not exist: %s", filePath)
			os.Exit(1)
		}

		dir := filepath.Dir(filePath)

		cmd0 := exec.New("sops", filePath)
		cmd0.Dir = dir
		o, _ := cmd0.Run()
		os.Exit(o.Code)
		// Implement the edit logic here
	},
}

func init() {
	editCmd.Flags().Bool("use-code", false, "Use vs code editor for editing")
	rootCmd.AddCommand(editCmd)
}

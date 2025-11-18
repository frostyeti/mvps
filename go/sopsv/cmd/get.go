package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get [KEY]",
	Short: "Get a secret from the secrets database",
	Long: `Get a secret from the secrets database using its URI and key.
	
If needed, use the --trim flag to trim whitespace from the secret value and not print as a new line.

Output for anything other than the secret is disabled by default, use the 
--debug flag to enable it to triage issues.
	`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 1 {
			color.Red("[ERROR]: You must provide a key to get a secret.")
			color.Yellow("Usage: xsops get [KEY]")
			os.Exit(1)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		vault, _ := cmd.Flags().GetString("vault")
		uriString := vault
		key := args[0]

		filePath, err := getFilePath(uriString)
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error getting file path: %v", err)
			}
			os.Exit(1)
		}

		dir := filepath.Dir(filePath)
		cmd0 := exec.New("sops", "decrypt", "--extract", "[\""+key+"\"]", filePath)
		cmd0.Dir = dir

		res, err := cmd0.Output()
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error executing sops command: %v", err)
			}
			os.Exit(1)
		}

		jsonRecord := string(res.Text())
		secretRecord := &SecretRecord{}
		err = json.Unmarshal([]byte(jsonRecord), secretRecord)
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error unmarshalling JSON: %v", err)
			}
			os.Exit(1)
		}

		trimit, _ := cmd.Flags().GetBool("trim")
		if trimit {
			secretRecord.Secret = strings.TrimSpace(secretRecord.Secret)
			os.Stdout.WriteString(secretRecord.Secret)
			os.Exit(0)
		}

		os.Stdout.WriteString(secretRecord.Secret + "\n")
		os.Exit(0)
	},
}

func init() {
	getCmd.Flags().Bool("trim", false, "Trim whitespace from the secret value and not print as new line")
	rootCmd.AddCommand(getCmd)
}

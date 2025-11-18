package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set [KEY]",
	Short: "Set a secret in the secrets database",
	Long: `Set a secret in the secrets database using its URI and key.
	
Use various flags to specify the secret value, expiration time, tags, and more.

To set the secret using standard input, use the --stdin flag.
To set the secret from a file, use the --file flag.
To set the secret from an environment variable, use the --env flag.
To directly set the secret value, use the --value flag. This should only be
used if you are wrapping the command in a script or similar and not
from the shell directly.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			color.Red("[ERROR]: You must provide a URI and a key to set a secret.")
			color.Yellow("Usage: xsops set [URI] [KEY]")
			os.Exit(1)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		vault, _ := cmd.Flags().GetString("vault")

		uriString := vault
		key := args[0]

		filePath, err := getFilePath(uriString)
		if err != nil {
			color.Red("[ERROR]: Error getting file path: %v", err)
			os.Exit(1)
		}

		dir := filepath.Dir(filePath)

		secretValue := ""
		inlineValue, _ := cmd.Flags().GetString("value")
		if inlineValue != "" {
			secretValue = inlineValue
		}

		if secretValue == "" {
			stdin, _ := cmd.Flags().GetBool("stdin")
			if stdin {
				stdinValue, err := io.ReadAll(os.Stdin)
				if err != nil {
					color.Red("[ERROR]: Error reading from stdin: %v", err)
					os.Exit(1)
				}
				secretValue = string(stdinValue)
			}
		}

		if secretValue == "" {
			filePathFlag, _ := cmd.Flags().GetString("file")
			if filePathFlag != "" {
				fileContent, err := os.ReadFile(filePathFlag)
				if err != nil {
					color.Red("[ERROR]: Error reading file: %v", err)
					os.Exit(1)
				}
				secretValue = strings.TrimSpace(string(fileContent))
			}
		}

		if secretValue == "" {
			envName, _ := cmd.Flags().GetString("env")
			if envName != "" {
				secretValue = os.Getenv(envName)
				if secretValue == "" {
					color.Red("[ERROR]: Environment variable %s is not set", envName)
					os.Exit(1)
				}
			}
		}

		cmd0 := exec.New("sops", "decrypt", "--extract", "[\""+key+"\"]", filePath)
		cmd0.Dir = dir

		res, _ := cmd0.Output()

		expiresAt, _ := cmd.Flags().GetString("expires-at")
		var expiresAtTime *time.Time
		if expiresAt != "" {
			t, err := time.Parse(time.RFC3339, expiresAt)
			if err != nil {
				color.Red("[ERROR]: Error parsing expiration time: %v", err)
				os.Exit(1)
			}
			expiresAtTime = &t
		}

		tags, _ := cmd.Flags().GetStringToString("tags")

		if res.Code != 0 && len(res.Stdout) == 0 {
			secretRecord1 := &SecretRecord{
				Secret:    secretValue,
				CreatedAt: time.Now().UTC(),
				Enabled:   true,
			}

			if expiresAtTime != nil {
				secretRecord1.ExpiresAt = expiresAtTime
			}

			if tags != nil {
				secretRecord1.Tags = make(map[string]*string, len(tags))
				for k, v := range tags {
					secretRecord1.Tags[k] = &v
				}
			}

			jsonContent, err := json.Marshal(secretRecord1)
			if err != nil {
				color.Red("[ERROR]: Error marshalling JSON: %v", err)
				os.Exit(1)
			}

			cmd1 := exec.New("sops", "set", filePath, "[\""+key+"\"]", string(jsonContent))
			cmd1.Dir = dir
			o, err := cmd1.Run()
			if err != nil {
				color.Red("[ERROR]: Error executing sops set command: %v", err)
				os.Exit(1)
			}

			os.Exit(o.Code)
		}

		jsonRecord := string(res.Text())
		var secretRecord SecretRecord
		err = json.Unmarshal([]byte(jsonRecord), &secretRecord)
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error unmarshalling JSON: %v", err)
			}
			os.Exit(1)
		}

		if secretValue != "" {
			secretRecord.Secret = secretValue
		}

		if expiresAtTime != nil {
			secretRecord.ExpiresAt = expiresAtTime
		}

		if tags != nil {
			secretRecord.Tags = make(map[string]*string, len(tags))
			for k, v := range tags {
				secretRecord.Tags[k] = &v
			}
		}

		secretRecord.UpdatedAt = time.Now().UTC()

		jsonBytes, err := json.Marshal(secretRecord)
		if err != nil {
			color.Red("[ERROR]: Error marshalling secret record to JSON: %v", err)
			os.Exit(1)
		}

		cmd1 := exec.New("sops", "set", filePath, "[\""+key+"\"]", string(jsonBytes))
		cmd1.Dir = dir

		o, err := cmd1.Run()
		if err != nil {
			color.Red("[ERROR]: Error executing sops set command: %v", err)
			os.Exit(1)
		}
		os.Exit(o.Code)
	},
}

func init() {
	setCmd.Flags().StringP("expires-at", "E", "", "Set expiration time for the secret (RFC3339 format)")
	setCmd.Flags().StringP("env", "e", "", "The environment variable to use for the secret value")
	setCmd.Flags().StringToStringP("tags", "t", nil, "Set tags for the secret (key=value pairs)")
	setCmd.Flags().BoolP("stdin", "S", false, "Read secret from stdin instead of command line argument")
	setCmd.Flags().StringP("file", "f", "", "Path to the file containing the secret (if not using stdin)")
	setCmd.Flags().StringP("value", "V", "", "Directly set the secret value (if not using stdin or file)")
	rootCmd.AddCommand(setCmd)
}

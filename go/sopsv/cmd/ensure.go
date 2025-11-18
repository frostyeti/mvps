package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/frostyeti/mvps/go/secrets"
	"github.com/spf13/cobra"
)

var ensureCmd = &cobra.Command{
	Use:   "ensure [KEY]",
	Short: "Ensures that the xsops secret database is initialized",
	Long: `Ensures that the xsops secret database is initialized in the specified directory.
	
If no secret exists, it generates a new secret with flags/options provided. By default
a new 32 character secret is generated with uppercase, lowercase, digits and symbols
included  which meets NIST SP 800-63B requirements.

The secret is stored in the xsops.secrets.json file in the specified directory and the
new secret is returned.
	
If needed, use the --trim flag to trim whitespace from the secret value and not print as
a new line.

Output for anything other than the secret is disabled by default, use the --debug flag
to enable it to triage issues.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			color.Red("[ERROR]: You must provide the KEY to get a secret.")
			color.Yellow("Usage: xsops -v <vault> get [KEY]")
			os.Exit(1)
		}

		vault, _ := cmd.Flags().GetString("vault")
		debug, _ := cmd.Flags().GetBool("debug")

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

		res, _ := cmd0.Output()

		if len(res.Stdout) > 0 && res.Code == 0 {
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

			os.Stdout.WriteString(secretRecord.Secret)
			os.Stdout.Write([]byte("\n"))
			os.Exit(0)
		}

		builder := secrets.NewOptionsBuilder()
		chars, _ := cmd.Flags().GetString("chars")
		size, _ := cmd.Flags().GetInt16("size")
		if size <= 0 {
			size = 32 // Default size if not specified
		}

		opts := []secrets.SetOption{}
		if chars != "" {
			opts = append(opts, secrets.WithChars(chars))
		} else {
			noUpper, _ := cmd.Flags().GetBool("no-upper")
			noLower, _ := cmd.Flags().GetBool("no-lower")
			noDigits, _ := cmd.Flags().GetBool("no-digits")
			noSymbols, _ := cmd.Flags().GetBool("no-symbols")
			symbols, _ := cmd.Flags().GetString("symbols")

			if !noUpper {
				opts = append(opts, secrets.WithUpper(!noUpper))
			}
			if !noLower {
				opts = append(opts, secrets.WithLower(!noLower))
			}
			if !noDigits {
				opts = append(opts, secrets.WithDigits(!noDigits))
			}
			if noSymbols {
				opts = append(opts, secrets.WithNoSymbols())
			} else if symbols != "" {
				opts = append(opts, secrets.WithSymbols(symbols))
			} else if symbols == "" {
				opts = append(opts, secrets.WithSymbols("_-@#^~`|=+{}[]"))
			}
		}

		masker := builder.Build()
		masker.Size = size
		secretValue, err := secrets.Generate(size, opts...)
		if secretValue == "" {
			color.Red("[ERROR]: Failed to generate secret value.")
			os.Exit(1)
		}

		if err != nil {
			if debug {
				color.Red("[ERROR]: Error generating secret: %v", err)
			}
			os.Exit(1)
		}

		newSecretRecord := &SecretRecord{
			Secret:    secretValue,
			CreatedAt: time.Now().UTC(),
			Enabled:   true,
		}

		jsonBytes, err := json.Marshal(newSecretRecord)
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error marshalling JSON: %v", err)
			}
			os.Exit(1)
		}

		cmd0 = exec.New("sops", "set", filePath, "[\""+key+"\"]", string(jsonBytes))
		cmd0.Dir = dir
		res, err = cmd0.Output()
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error executing sops set command: %v", err)
				color.Red("[DEBUG]: Command output: %s", res.Text())
			}
			os.Exit(1)
		}

		trimit, _ := cmd.Flags().GetBool("trim")
		if trimit {
			os.Stdout.WriteString(strings.TrimSpace(secretValue))
			os.Exit(0)
		}

		os.Stdout.WriteString(secretValue + "\n")
		os.Exit(res.Code)
	},
}

func init() {
	rootCmd.AddCommand(ensureCmd)
	ensureCmd.Flags().Int16P("size", "s", 0, "Size of the secret to ensure")
	ensureCmd.Flags().BoolP("no-upper", "U", false, "Do not include uppercase letters in the secret")
	ensureCmd.Flags().BoolP("no-lower", "L", false, "Do not include lowercase letters in the secret")
	ensureCmd.Flags().BoolP("no-digits", "D", false, "Do not include numbers in the secret")
	ensureCmd.Flags().BoolP("no-symbols", "S", false, "Do not include symbols in the secret")
	ensureCmd.Flags().String("symbols", "_-@#^~`|=+{}[]", "Custom symbols to include in the secret")
	ensureCmd.Flags().Bool("trim", false, "Trim whitespace from the secret value and not print as new line")
	ensureCmd.Flags().StringP("chars", "c", "", "Custom characters to include in the secret")
}

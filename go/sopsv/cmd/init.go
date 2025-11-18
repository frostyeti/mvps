package cmd

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initializes xsops secret database in the specified directory",
	Long: `Initializes xsops secret database in the specified directory.
	
	If no directory is specified, it defaults to the user's home data directory.
	If no age key for sops is found, it generates a new one in the user's 
	home config directory.

	It creates a default sops configuration file and an empty secrets file 
	the directory.  The default name for a secrets file is xsops.secrets.json.`,
	Run: func(cmd *cobra.Command, args []string) {
		os.Setenv("XSOPS_CONFIG_HOME", "")
		homeConfig, err := os.UserConfigDir()

		if err != nil {
			color.Red("[ERROR]: Error getting home config: %v", err)
			os.Exit(1)
		}

		sopsAgeKey := filepath.Join(homeConfig, "sops", "age", "keys.txt")
		xsopsDefaultSopsConfig := filepath.Join(homeConfig, "xsops", ".sops.yaml")
		if _, err := os.Stat(sopsAgeKey); os.IsNotExist(err) {
			dir := filepath.Dir(sopsAgeKey)
			if err := os.MkdirAll(dir, 0700); err != nil {
				color.Red("[ERROR]: Error creating directory: %v", err)
				os.Exit(1)
			}

			exec.New("age-keygen", "-o", sopsAgeKey).Run()

		}

		if _, err := os.Stat(xsopsDefaultSopsConfig); os.IsNotExist(err) {
			keyContent, err := os.ReadFile(sopsAgeKey)
			if err != nil {
				color.Red("[ERROR]: Error reading age key file: %v", err)
				os.Exit(1)
			}
			publicKey := ""
			// read second line of the key file
			// get the public key and strip "public key: " from the beginning
			scanner := bufio.NewScanner(strings.NewReader(string(keyContent)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "# public key: ") {
					pk := strings.TrimPrefix(line, "# public key: ")
					publicKey = strings.TrimSpace(pk)
					break
				}
			}

			sopsConfig := `
# SOPS configuration file
creation_rules:
  - encrypted_regex: '^(secret)$'
    age: >-
      ` + publicKey + `
`

			if err := os.WriteFile(xsopsDefaultSopsConfig, []byte(sopsConfig), 0644); err != nil {
				color.Red("[ERROR]: Error writing sops config file: %v", err)
				os.Exit(1)
			}
		}

		vault, _ := cmd.Flags().GetString("vault")
		debug, _ := cmd.Flags().GetBool("debug")

		uriString := vault

		fileName, err := getFilePath(uriString)
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error getting file path: %v", err)
			}
			os.Exit(1)
		}

		dir := filepath.Dir(fileName)
		sopsFile := filepath.Join(dir, ".sops.yaml")

		if _, err := os.Stat(sopsFile); os.IsNotExist(err) {
			configBytes, err := os.ReadFile(xsopsDefaultSopsConfig)
			if err != nil {
				color.Red("[ERROR]: Error reading default sops config: %v", err)
				os.Exit(1)
			}

			if _, err := os.Stat(dir); os.IsNotExist(err) {
				if err := os.MkdirAll(dir, 0755); err != nil {
					color.Red("[ERROR]: Error creating directory: %v", err)
					os.Exit(1)
				}
			}

			if err := os.WriteFile(sopsFile, configBytes, 0644); err != nil {
				color.Red("[ERROR]: Error writing sops config file: %v", err)
				os.Exit(1)
			}
		}

		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				color.Red("[ERROR]: Error creating directory: %v", err)
				os.Exit(1)
			}

			if err := os.WriteFile(fileName, []byte("{}"), 0644); err != nil {
				color.Red("[ERROR]: Error writing secrets file: %v", err)
				os.Exit(1)
			}

			o, err := exec.New("sops", "encrypt", "-i", fileName).WithCwd(dir).Run()
			if err != nil {
				color.Red("[ERROR]: Error encrypting secrets file: %v", err)
				os.Exit(1)
			}

			os.Exit(o.Code)
		}
	},
}

func init() {
	initCmd.Flags().BoolP("debug", "D", false, "Enable debug mode")
	rootCmd.AddCommand(initCmd)
}

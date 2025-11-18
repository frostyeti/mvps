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

var rmCmd = &cobra.Command{
	Use:   "rm [KEY]",
	Short: "Remove a secret from the secrets database",
	Long:  `Remove a secret from the secrets database using its URI and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			color.Red("[ERROR]: You must provide a URI and a key to remove a secret.")
			color.Yellow("Usage: xsops rm [URI] [KEY]")
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

		cmd0 := exec.New("sops", "decrypt", filePath)
		cmd0.Dir = dir

		res, _ := cmd0.Output()
		if res.Code != 0 {
			color.Red("[ERROR]: Error decrypting file: %v", res.Stderr)
			os.Exit(1)
		}

		data := map[string]interface{}{}
		if err := json.Unmarshal(res.Stdout, &data); err != nil {
			color.Red("[ERROR]: Error unmarshalling JSON: %v", err)
			os.Exit(1)
		}

		if _, exists := data[key]; !exists {
			color.Yellow("[WARNING]: Key '%s' does not exist in the secret database.", key)
			os.Exit(0)
		}

		delete(data, key)

		jsonBytes, err := json.Marshal(data)
		if err != nil {
			color.Red("[ERROR]: Error marshalling JSON: %v", err)
			os.Exit(1)
		}

		cmd0 = exec.New("sops", "encrypt", "--filename-override", filePath)
		jsonString := string(jsonBytes)
		cmd0.Stdin = strings.NewReader(jsonString)
		cmd0.Dir = dir
		res, _ = cmd0.Output()
		if res.Code != 0 {
			color.Red("[ERROR]: Error encrypting file: %s", res.ErrorText())
			color.Red("%s", res.Text())
			os.Exit(1)
		}

		encryptedData := res.Stdout
		if err := os.WriteFile(filePath, encryptedData, 0644); err != nil {
			color.Red("[ERROR]: Error writing encrypted file: %v", err)
			os.Exit(1)
		}

		os.Stdout.WriteString("Secret removed successfully." + "\n")
		os.Exit(0)
	},
}

func init() {
	rmCmd.Flags().BoolP("debug", "d", false, "Enable debug mode")
	rootCmd.AddCommand(rmCmd)
}

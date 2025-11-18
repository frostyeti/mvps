package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/frostyeti/mvps/go/exec"
	"github.com/gobwas/glob"
	"github.com/spf13/cobra"
)

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List all secrets in the secrets database",
	Long: `List all secrets in the secrets database using its URI.
	
Use the --match flag to filter secrets by glob pattern.`,
	Example: `xsops -v default ls
	xsops default ls --match "*prod*"
	xsops -v ./xsops.secrets.json ls 
	xsops -v sops:///path/to/secrets.json ls `,
	Run: func(cmd *cobra.Command, args []string) {
		debug, _ := cmd.Flags().GetBool("debug")
		vault, _ := cmd.Flags().GetString("vault")
		uriString := vault

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

		res, err := cmd0.Output()
		if err != nil {
			if debug {
				color.Red("[ERROR]: Error executing sops command: %v", err)
			}
			os.Exit(1)
		}

		var secrets map[string]interface{}
		if err := json.Unmarshal(res.Stdout, &secrets); err != nil {
			if debug {
				color.Red("[ERROR]: Error unmarshalling JSON: %v", err)
			}
			os.Exit(1)
		}

		filter, _ := cmd.Flags().GetString("filter")
		if filter == "" {
			for key := range secrets {
				if key != "sops" {
					color.Blue("%s", key)
				}
			}
		} else {
			g := glob.MustCompile(filter)
			for key := range secrets {
				if key != "sops" && g.Match(key) {
					color.Blue("%s", key)
				}
			}
		}

		os.Exit(0)
	},
}

func init() {
	lsCmd.Flags().BoolP("debug", "d", false, "Enable debug mode")
	lsCmd.Flags().StringP("match", "m", "", "Filter secrets by glob pattern")
	rootCmd.AddCommand(lsCmd)
}

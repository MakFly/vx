package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vx",
	Short: "VX — Security scanner for web applications",
	Long: `VX is a fast, multi-module security scanner for web applications.
It performs black-box (remote) and white-box (local) security auditing
with scoring, detailed findings, and remediation guidance.`,
	Run: func(cmd *cobra.Command, args []string) {
		runInteractive()
	},
}

func Execute() error {
	checkDisclaimer()
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Version
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("vx v0.1.0")
		},
	})

	// Banner on help
	rootCmd.SetHelpTemplate(banner + rootCmd.HelpTemplate())
}

func exitError(msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	os.Exit(1)
}

const banner = `
  ██╗   ██╗██╗  ██╗
  ██║   ██║╚██╗██╔╝
  ██║   ██║ ╚███╔╝  Security Scanner v0.1.0
  ╚██╗ ██╔╝ ██╔██╗
   ╚████╔╝ ██╔╝ ██╗
    ╚═══╝  ╚═╝  ╚═╝

`

// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
	"os"
	// "strings"
	// "github.com/chaosinthecrd/dexter/pkg/output"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mandark",
	Short: "check images found with dexter against cosign policy",
	Long:  `Dexter is a CLI tool to check assess container images references against cosign policy.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var OutputMode string
var PolicyFile string
var ImageFile string
var DebugMode bool

func init() {
      // TODO: Implement output mode
      // rootCmd.PersistentFlags().StringVarP(&OutputMode, "output", "o", "pretty", "Output mode. Supported modes: "+strings.Join(output.Modes, ", "))
      rootCmd.PersistentFlags().StringVarP(&ImageFile, "image-reference-file", "i", "", "JSON file containing image references to be assessed against policy. Can be generated using Dexter.")
      rootCmd.PersistentFlags().StringVarP(&PolicyFile, "policy-file", "p", "policy.yaml", "Policy file (rego or cue) that is used to assess image references with the chosen policy engine.")
      rootCmd.PersistentFlags().BoolVar(&DebugMode, "debug", false, "Increase the verbosity of logs with debug mode")
}

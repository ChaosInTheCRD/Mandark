// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
  "context"
  "fmt"

	apex "github.com/apex/log"

	"github.com/chaosinthecrd/mandark/pkg/config"
	"github.com/chaosinthecrd/mandark/pkg/files"
	"github.com/chaosinthecrd/mandark/internal/log"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the provided image refereneces in the image file meet the policy defined in the policy file.",
	RunE: func(cmd *cobra.Command, args []string) error {
           ctx := log.InitLogContext(DebugMode)
           if err := verify(ctx); err != nil {
              logs := apex.FromContext(ctx)
              logs.Error("command 'verify' failed. Closing.")
           }

           return nil
     },
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func manipulate(ctx context.Context) error {

          logs :=  apex.FromContext(ctx)

          // err := output.ValidateOutputMode(OutputMode)
          // if err != nil {
          //    logs.Errorf("Failed to validate output mode")
          //    return err
          // }

          var err error

          logs = log.AddFields(logs, "verify")

          logs.Debugf("Verifying image references defined in %s against policy defined in %s", ImageFile, PolicyFile)


          images, err := config.InitialiseImageFile(ImageFile)
          if err != nil {
             logs.Errorf("Failed to initialise mandark image file: %s", err.Error())
             return err
          }


          defer fmt.Printf("had image references that were manipulated:\n")
          defer fmt.Printf("\n")

          return nil
}

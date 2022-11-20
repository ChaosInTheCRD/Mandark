// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	apex "github.com/apex/log"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/chaosinthecrd/mandark/internal/log"
	"github.com/chaosinthecrd/mandark/pkg/config"
	p "github.com/chaosinthecrd/mandark/pkg/policy"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the provided image refereneces in the image file meet the policy defined in the policy file.",
	RunE: func(cmd *cobra.Command, args []string) error {
           ctx := log.InitLogContext(DebugMode)
           if err := verify(ctx, args); err != nil {
              logs := apex.FromContext(ctx)
              logs.Error("command 'verify' failed. Closing.")
           }

           return nil
     },
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func verify(ctx context.Context, args []string) error {

          logs :=  apex.FromContext(ctx)

          // err := output.ValidateOutputMode(OutputMode)
          // if err != nil {
          //    logs.Errorf("Failed to validate output mode")
          //    return err
          // }

          var err error

          logs = log.AddFields(logs, "verify", PolicyFile, ImageFile)

          logs.Debugf("Verifying image references defined in %s against policy defined in %s", ImageFile, PolicyFile)

          policy, err := config.InitialisePolicy(PolicyFile)
          if err != nil {
            logs.Errorf("Failed to initialise policy file: %s", err.Error())
          }

          fmt.Println(policy)

          images := config.Images{}
          if ImageFile != "" {
            images, err = config.InitialiseImages(ImageFile)
            if err != nil {
               logs.Errorf("Failed to initialise mandark image file: %s", err.Error())
               return err
            }
          } else {
            if len(args) == 0 {
              logs.Errorf("Either an image file or image reference argument(s) must be specified")
              return nil
            }
            for _, n := range(args) {
              ref, err := name.ParseReference(n)
              if err != nil {
                logs.Errorf("Failed to parse string %s as image reference: %s", err.Error())
              }
              images.ImageReferences = append(images.ImageReferences, ref)

            }
          }

          results, errs := p.VerifyImages(policy, images)
          if errs != nil {
            logs.Errorf("Failed to verify images:")
            for _, n := range(errs) {
              logs.Errorf("%s", n)
            }
            return nil
          }

          fmt.Printf("Results %v", results)

          return nil
}

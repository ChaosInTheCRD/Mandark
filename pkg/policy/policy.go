package policy

import (
	"context"
  "errors"
  "strings"

	"github.com/chaosinthecrd/mandark/pkg/config"
	"github.com/google/go-containerregistry/pkg/name"
  "github.com/sigstore/policy-controller/pkg/webhook"
  "github.com/sigstore/policy-controller/pkg/apis/glob"
	webhookv1alpha1 "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/google/go-containerregistry/pkg/authn"
	"knative.dev/pkg/apis"

)


func VerifyImages(ctx context.Context, cip webhookv1alpha1.ClusterImagePolicy, refs config.Images) (*[]webhook.PolicyResult, []OutputErr) {

  var (
    results = []webhook.PolicyResult{}
    ns = "unused"
    outputErrs = []OutputErr{}
    remoteOpts = []ociremote.Option{
      ociremote.WithRemoteOptions(
        remote.WithAuthFromKeychain(authn.DefaultKeychain),
      ),
    }
  )

  for _, n := range(refs.ImageReferences) {
    // Don't need to check for errors as image have already been validated
    ref, _ := name.ParseReference(n)
    result, errs := webhook.ValidatePolicy(ctx, ns, ref, cip, remoteOpts...)

    if errs != nil {
    outputErrs = append(outputErrs, FormatOutputErrors(ref, errs))
    }

    if result != nil {
      results = append(results, *result)
    }
  }

    return &results, outputErrs
}

func ValidatePolicy(ctx context.Context, image string, cip webhookv1alpha1.ClusterImagePolicy) (webhook.PolicyResult, []error) {
  return webhook.PolicyResult{}, []error{};
}


func MatchImageGlob(image string, cip webhookv1alpha1.ClusterImagePolicy) (bool, error) {

	matches := false

	for _, pattern := range cip.Images {
		if pattern.Glob != "" {
			if matched, err := glob.Match(pattern.Glob, image); err != nil {
        continue
			} else if matched { 
				matches = true
			}
		}
	}

  return matches, nil
}

func FormatOutputErrors(image name.Reference, errs []error) (OutputErr) {

    outputErr := OutputErr{}

    for _, err := range errs {
      var fe *apis.FieldError
      if errors.As(err, &fe) {
        if warnFE := fe.Filter(apis.WarningLevel); warnFE != nil {
          outputErr.Warnings = append(outputErr.Warnings, strings.Trim(warnFE.Error(), "\n"))
        }
        if errorFE := fe.Filter(apis.ErrorLevel); errorFE != nil {
          outputErr.Errors = append(outputErr.Errors, strings.Trim(errorFE.Error(), "\n"))
        }
      } else {
        outputErr.Other = append(outputErr.Other, strings.Trim(err.Error(), "\n"))
      }
    }
    
    return outputErr
}

type OutputErr struct {
  Errors []string `json:"errors"`
  Warnings []string `json:"warnings"`
  Other []string `json:"other"`
}

package config

import (
	"context"
	"encoding/json"
	"os"

	apex "github.com/apex/log"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	webhookv1alpha1 "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	"knative.dev/pkg/apis"
	"sigs.k8s.io/yaml"
)

type Images struct {
   ImageReferences []string `yaml:"ImageReferencees"`
}

func InitialiseImages(imageFile string) (Images, error) {

   images := Images{}

   file, err := os.ReadFile(imageFile) 
   if err != nil {
     return Images{}, err
   }

   err = yaml.Unmarshal(file, &images) 
   if err != nil {
     return Images{}, err
   }

   for _, n := range(images.ImageReferences) { 
     _, err := name.ParseReference(n)
     if err != nil {
       return images, err
     }
   }

   return images, nil
}

func InitialisePolicy(ctx context.Context, policyFile string) (webhookv1alpha1.ClusterImagePolicy, error) {

  logs := apex.FromContext(ctx)

  file, err := os.ReadFile(policyFile)
  if err != nil {
    return webhookv1alpha1.ClusterImagePolicy{}, err
  }

  var v1alpha1cip v1alpha1.ClusterImagePolicy
  if err := yaml.Unmarshal(file, &v1alpha1cip); err != nil {
      return webhookv1alpha1.ClusterImagePolicy{}, err
  }

  v1alpha1cip.SetDefaults(ctx)

	defaulted, err := yaml.Marshal(v1alpha1cip)
	if err != nil {
      return webhookv1alpha1.ClusterImagePolicy{}, err
	}

  logs.Debugf("Using the following policy:\n%s", defaulted)

	validateErrs := v1alpha1cip.Validate(ctx)
	if validateErrs != nil {
		// CIP validation can return Warnings so let's just go through them
		// and only exit if there are Errors.
		if warnFE := validateErrs.Filter(apis.WarningLevel); warnFE != nil {

			logs.Debugf("CIP has warnings:\n%s\n", warnFE.Error())
		}
		if errorFE := validateErrs.Filter(apis.ErrorLevel); errorFE != nil {
			logs.Fatalf("CIP is invalid: %s", errorFE.Error())
		}
	}

	cip := webhookv1alpha1.ConvertClusterImagePolicyV1alpha1ToWebhook(&v1alpha1cip)

	// We have to marshal/unmarshal the CIP since that handles converting
	// inlined Data into PublicKey objects that validator uses.
	webhookCip, err := json.Marshal(cip)
	if err != nil {
    return webhookv1alpha1.ClusterImagePolicy{}, err
	}
	if err := json.Unmarshal(webhookCip, &cip); err != nil {
    return webhookv1alpha1.ClusterImagePolicy{}, err
	}

  return *cip, nil
}


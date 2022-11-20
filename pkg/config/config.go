package config

import (
	"fmt"
	"os"
	"knative.dev/pkg/apis"

	"github.com/google/go-containerregistry/pkg/name"
	webhookpolicy "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
  policyv1alpha1 "github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"gopkg.in/yaml.v3"
)

type Images struct {
   ImageReferences []name.Reference `yaml:"ImageReferencees"`
}

func InitialiseImages(imageFile string) (Images, error) {

   config := Images{}
   if imageFile != "" {
      file, err := os.ReadFile(imageFile)
      if err != nil {
         return Images{}, err
      }

      err = yaml.Unmarshal(file, &config)
      if err != nil {
         return Images{}, err
      }

   } else {
     return Images{}, fmt.Errorf("Image file not specified.")
   }

   return config, nil
}

func InitialisePolicy(policyFile string) (webhookpolicy.ClusterImagePolicy, error) {

  cip := webhookpolicy.ClusterImagePolicy{}
  if policyFile != "" {
    file, err := os.ReadFile(policyFile)
    if err != nil {
      return cip, err
    }

    _, err = apis.ParseURL("https://fulcio.sigstore.dev")
    if err != nil {
      fmt.Println(err.Error())
      panic(err)
    }

    ocip := policyv1alpha1.ClusterImagePolicy{}
    err = yaml.Unmarshal(file, &ocip)
    if err != nil {
      return cip, err
    }
    
    cip = *webhookpolicy.ConvertClusterImagePolicyV1alpha1ToWebhook(&ocip)
  }

  return cip, nil

}


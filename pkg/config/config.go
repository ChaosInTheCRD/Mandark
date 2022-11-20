package config

import (
  "gopkg.in/yaml.v3"
	"os"
  "github.com/google/go-containerregistry/name"
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

   }

   return config, nil
}


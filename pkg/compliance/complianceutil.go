package compliance

import (
	"fmt"
	"github.com/gobuffalo/packr/v2"
	"gopkg.in/yaml.v2"
)

func LoadClusterComplianceSpecs() ([]Spec, error) {
	specs := make([]Spec, 0)
	specPath := "./specs/"
	box := packr.Folder(specPath)
	// Add Master Node Configuration tests
	fileList := box.List()
	for _, file := range fileList {
		specString, err := box.FindString(fmt.Sprintf("%s%s", "./", file))
		if err != nil {
			fmt.Errorf(fmt.Sprintf("failed to load compliance specs %s", err.Error()))
		}
		var spec Spec
		err = yaml.Unmarshal([]byte(specString), &spec)
		if err != nil {
			fmt.Errorf(fmt.Sprintf("failed to load compliance specs %s", err.Error()))
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

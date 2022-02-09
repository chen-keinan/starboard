package compliance

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/mapper"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/emirpasic/gods/sets/hashset"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	//KubeBench tool name as appear in spec file
	KubeBench = "kube-bench"
	//ConfAudit tool name as appear in spec file
	ConfAudit = "conf-audit"
)

type Writer interface {
	Write(ctx context.Context) error
}

type Reader interface {
	FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type rw struct {
	client client.Client
}

type ControlsSummary struct {
	ID    string
	Pass  float32
	Total float32
}

type SpecDataMapping struct {
	toolResourceListNames map[string]*hashset.Set
	toolControl           map[string][]string
	controlResourceList   map[string]*hashset.Set
	controlCheckIds       map[string][]string
	resourceCheckIds      map[string][]string
}

func (w *rw) Write(ctx context.Context, spec Spec) error {
	smd := w.populateSpecDataToMaps(spec)
	toolResourceMap, err := w.findComplianceToolToResource(ctx, smd.toolResourceListNames)
	if err != nil {
		return err
	}
	resourceRowData := make(map[string][]map[string]mapper.CheckDetails)
	toolMapper := make(map[string]mapper.Mapper)
	controlsSummary := make([]ControlsSummary, 0)
	for tool, controls := range smd.toolControl {
		resourceMap, ok := toolResourceMap[tool]
		if !ok {
			continue
		}
		if _, ok := toolMapper[tool]; !ok {
			toolMapper[tool] = mapper.ByTool(tool)
		}
		//iterate controls
		for _, control := range controls {
			// fetch resources row data by tool
			for _, resourceName := range smd.controlResourceList[control].Values() {
				rName := resourceName.(string)
				if _, ok := resourceRowData[rName]; !ok {
					resourceRowData[rName] = toolMapper[tool].MapReportDataToMap(resourceMap[rName], smd.resourceCheckIds[resourceName.(string)])
				}
				for _, check := range smd.controlCheckIds[control] {
					pass := 0.0
					total := 0.0
					if len(resourceRowData[rName]) == 0 {
						total++
					}
					for _, row := range resourceRowData[rName] {
						if _, ok := row[check]; !ok {
							continue
						}
						if row[check].Status == "pass" {
							pass++
						}
						total++
					}
					if pass == 0 && total == 0 {
						total = 1
					}
					controlsSummary = append(controlsSummary, ControlsSummary{ID: control, Pass: float32(pass), Total: float32(total)})
				}
			}
		}
		for _, control := range controlsSummary {
			fmt.Println(fmt.Sprintf("control:%s  compliance:%f", control.ID, control.Pass/control.Total*100))
		}
	}
	return nil
}

func (w *rw) populateSpecDataToMaps(spec Spec) *SpecDataMapping {
	//tool to control map
	toolControl := make(map[string][]string, 0)
	//control to resource list map
	controlResourceList := make(map[string]*hashset.Set)
	//control to checks map
	controlCheckIds := make(map[string][]string)
	//tool to resource list map
	toolResourceListName := make(map[string]*hashset.Set)
	// resource to checkIds
	resourceChecksIds := make(map[string][]string)
	for _, control := range spec.Controls {
		if _, ok := toolResourceListName[control.Tool]; !ok {
			toolResourceListName[control.Tool] = hashset.New()
		}
		if _, ok := controlResourceList[control.ID]; !ok {
			controlResourceList[control.ID] = hashset.New()
		}
		for _, resource := range control.Resources {
			controlResourceList[control.ID].Add(resource)
			toolResourceListName[control.Tool].Add(resource)
			for _, check := range control.Checks {
				if _, ok := resourceChecksIds[resource]; !ok {
					resourceChecksIds[resource] = make([]string, 0)
				}
				resourceChecksIds[resource] = append(resourceChecksIds[resource], check.ID)
			}
		}
		// update tool control map
		if _, ok := toolControl[control.Tool]; !ok {
			toolControl[control.Tool] = make([]string, 0)
		}
		toolControl[control.Tool] = append(toolControl[control.Tool], control.ID)
		//update control resource list map
		for _, check := range control.Checks {
			if _, ok := controlCheckIds[control.ID]; !ok {
				controlCheckIds[control.ID] = make([]string, 0)
			}
			controlCheckIds[control.ID] = append(controlCheckIds[control.ID], check.ID)
		}
	}
	return &SpecDataMapping{
		toolControl:           toolControl,
		toolResourceListNames: toolResourceListName,
		controlResourceList:   controlResourceList,
		controlCheckIds:       controlCheckIds,
		resourceCheckIds:      resourceChecksIds}
}

func NewReadWriter(client client.Client) *rw {
	return &rw{
		client: client,
	}
}

func (w *rw) FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error) {

	return nil, nil
}

func (w *rw) findComplianceToolToResource(ctx context.Context, resourceListNames map[string]*hashset.Set) (map[string]map[string]client.ObjectList, error) {
	toolResource := make(map[string]map[string]client.ObjectList)
	for tool, objNames := range resourceListNames {
		for _, objName := range objNames.Values() {
			objNameString, ok := objName.(string)
			if !ok {
				continue
			}
			labels := map[string]string{
				starboard.LabelResourceKind: objNameString,
			}
			matchingLabel := client.MatchingLabels(labels)
			objList := getObjListByName(tool)
			err := w.client.List(ctx, objList, matchingLabel)
			if err != nil {
				continue
			}
			if _, ok := toolResource[tool]; !ok {
				toolResource[tool] = make(map[string]client.ObjectList)
			}
			toolResource[tool][objNameString] = objList
		}
	}
	return toolResource, nil
}

func getObjListByName(toolName string) client.ObjectList {
	switch toolName {
	case KubeBench:
		return &v1alpha1.CISKubeBenchReportList{}
	case ConfAudit:
		return &v1alpha1.ConfigAuditReportList{}
	default:
		return nil
	}
}

type ToolResource struct {
	ToolResource map[string]map[string]interface{}
}

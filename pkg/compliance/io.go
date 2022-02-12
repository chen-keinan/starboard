package compliance

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/plugin/compliance"
	"github.com/emirpasic/gods/sets/hashset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

type Writer interface {
	Write(ctx context.Context) error
}

type ReadWriter interface {
	Writer
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
	toolResourceListNames  map[string]*hashset.Set
	controlIDControlObject map[string]Control
	controlCheckIds        map[string][]string
}

func (w *rw) Write(ctx context.Context, spec Spec) error {
	// map spec to key/value map for easy processing
	smd := w.populateSpecDataToMaps(spec)
	// map compliance tool to resource data
	toolResourceMap, err := compliance.MapComplianceToolToResource(w.client, ctx, smd.toolResourceListNames)
	if err != nil {
		return err
	}
	// organized data by check id and it aggregated results
	checkIdsToResults, err := w.checkIdsToResults(toolResourceMap)
	if err != nil {
		return err
	}
	// map tool checks results to control check results
	controlChecks := w.controlChecksByToolChecks(smd, checkIdsToResults)
	// publish compliance report
	return w.createComplianceReport(ctx, spec, controlChecks)
}

func (w *rw) createComplianceReport(ctx context.Context, spec Spec, controlChecks []v1alpha1.ControlCheck) error {
	var totalFail, totalPass int
	for _, controlCheck := range controlChecks {
		controlCheck.FailTotal = controlCheck.FailTotal + totalFail
		controlCheck.PassTotal = controlCheck.PassTotal + totalPass
	}
	summary := v1alpha1.ClusterComplianceSummary{PassCount: totalPass, FailCount: totalFail}
	report := v1alpha1.ClusterComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: spec.Name,
		},

		Report: v1alpha1.ClusterComplianceReportData{UpdateTimestamp: metav1.NewTime(time.Now()), Summary: summary, Type: v1alpha1.Compliance{Name: spec.Name, Description: spec.Description, Version: spec.Version}, ControlChecks: controlChecks},
	}
	var existing v1alpha1.ClusterComplianceReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: spec.Name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return w.client.Update(ctx, copied)
	}
	if errors.IsNotFound(err) {
		return w.client.Create(ctx, &report)
	}
	return err
}

func (w *rw) controlChecksByToolChecks(smd *SpecDataMapping, checkIdsToResults map[string][]*compliance.ToolCheckResult) []v1alpha1.ControlCheck {
	controlChecks := make([]v1alpha1.ControlCheck, 0)
	for controlID, checkIds := range smd.controlCheckIds {
		var passTotal, failTotal, total int
		for _, checkId := range checkIds {
			results, ok := checkIdsToResults[checkId]
			if ok {
				for _, checkResult := range results {
					for _, crd := range checkResult.Details {
						switch crd.Status {
						case compliance.Pass, compliance.Warn:
							passTotal++
						case compliance.Fail:
							failTotal++
						}
						total++
					}
				}
			}
		}
		control := smd.controlIDControlObject[controlID]
		controlChecks = append(controlChecks, v1alpha1.ControlCheck{ID: controlID, Name: control.Name, Description: control.Description, PassTotal: passTotal, FailTotal: failTotal})
	}
	return controlChecks
}

func (w *rw) checkIdsToResults(toolResourceMap map[string]map[string]client.ObjectList) (map[string][]*compliance.ToolCheckResult, error) {
	checkIdsToResults := make(map[string][]*compliance.ToolCheckResult)
	for tool, resourceListMap := range toolResourceMap {
		for resourceName, resourceList := range resourceListMap {
			mapper, err := compliance.ByTool(tool)
			if err != nil {
				return nil, err
			}
			idCheckResultMap := mapper.MapReportDataToMap(resourceName, resourceList)
			if idCheckResultMap == nil {
				continue
			}
			for id, toolCheckResult := range idCheckResultMap {
				if _, ok := checkIdsToResults[id]; !ok {
					checkIdsToResults[id] = make([]*compliance.ToolCheckResult, 0)
				}
				checkIdsToResults[id] = append(checkIdsToResults[id], toolCheckResult)
			}
		}
	}
	return checkIdsToResults, nil
}

func (w *rw) populateSpecDataToMaps(spec Spec) *SpecDataMapping {
	//control to resource list map
	controlIDControlObject := make(map[string]Control)
	//control to checks map
	controlCheckIds := make(map[string][]string)
	//tool to resource list map
	toolResourceListName := make(map[string]*hashset.Set)
	for _, control := range spec.Controls {
		if _, ok := toolResourceListName[control.Mapping.Tool]; !ok {
			toolResourceListName[control.Mapping.Tool] = hashset.New()
		}
		for _, resource := range control.Resources {
			toolResourceListName[control.Mapping.Tool].Add(resource)
		}
		controlIDControlObject[control.ID] = control
		//update control resource list map
		for _, check := range control.Mapping.Checks {
			if _, ok := controlCheckIds[control.ID]; !ok {
				controlCheckIds[control.ID] = make([]string, 0)
			}
			controlCheckIds[control.ID] = append(controlCheckIds[control.ID], check.ID)
		}
	}
	return &SpecDataMapping{
		toolResourceListNames:  toolResourceListName,
		controlIDControlObject: controlIDControlObject,
		controlCheckIds:        controlCheckIds}
}

func NewReadWriter(client client.Client) *rw {
	return &rw{
		client: client,
	}
}

type ToolResource struct {
	ToolResource map[string]map[string]interface{}
}

package compliance

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/emirpasic/gods/sets/hashset"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

const (
	//Fail check Status
	Fail = "fail"
	//Warn check Status
	Warn = "warn"
	// Pass check Status
	Pass = "pass"
	//KubeBench tool name as appear in spec file
	KubeBench = "kube-bench"
	//ConfigAudit tool name as appear in spec file
	ConfigAudit = "config-audit"
)

type Mapper interface {
	MapReportDataToMap(objType string, objList client.ObjectList) map[string]*ToolCheckResult
}

type kubeBench struct {
}

type configAudit struct {
}

func ByTool(tool string) (Mapper, error) {
	switch tool {
	case KubeBench:
		return &kubeBench{}, nil
	case ConfigAudit:
		return &configAudit{}, nil
	}
	// tool is not supported
	return nil, fmt.Errorf("mapper tool is not supported")
}

type CheckDetails struct {
	ID          string
	Status      string
	Remediation string
}

func (kb kubeBench) MapReportDataToMap(objType string, objList client.ObjectList) map[string]*ToolCheckResult {
	toolCheckResultMap := make(map[string]*ToolCheckResult, 0)
	cb := objList.(*v1alpha1.CISKubeBenchReportList)
	for _, item := range cb.Items {
		name := item.GetName()
		nameSpace := item.Namespace
		for _, section := range item.Report.Sections {
			for _, check := range section.Tests {
				for _, result := range check.Results {
					if _, ok := toolCheckResultMap[result.TestNumber]; !ok {
						toolCheckResultMap[result.TestNumber] = &ToolCheckResult{ID: result.TestNumber, Remediation: result.Remediation, ObjectType: objType}
						toolCheckResultMap[result.TestNumber].Details = make([]ResultDetails, 0)
					}
					toolCheckResultMap[result.TestNumber].Details = append(toolCheckResultMap[result.TestNumber].Details, ResultDetails{Name: name, Namespace: nameSpace, Status: strings.ToLower(result.Status)})
				}
			}
		}
	}
	return toolCheckResultMap
}

func (ac configAudit) MapReportDataToMap(objType string, objList client.ObjectList) map[string]*ToolCheckResult {
	toolCheckResultMap := make(map[string]*ToolCheckResult, 0)
	cb := objList.(*v1alpha1.ConfigAuditReportList)
	if len(cb.Items) == 0 {
		return nil
	}
	for _, item := range cb.Items {
		name := item.GetName()
		nameSpace := item.Namespace
		for _, check := range item.Report.Checks {
			if _, ok := toolCheckResultMap[check.ID]; !ok {
				toolCheckResultMap[check.ID] = &ToolCheckResult{ID: check.ID, Remediation: check.Remediation, ObjectType: objType}
				toolCheckResultMap[check.ID].Details = make([]ResultDetails, 0)
			}
			var status = Fail
			if check.Success {
				status = Pass
			}
			toolCheckResultMap[check.ID].Details = append(toolCheckResultMap[check.ID].Details, ResultDetails{Name: name, Namespace: nameSpace, Status: status})

		}
	}
	return toolCheckResultMap
}

func FindComplianceToolToResource(cli client.Client, ctx context.Context, resourceListNames map[string]*hashset.Set) (map[string]map[string]client.ObjectList, error) {
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
			err := cli.List(ctx, objList, matchingLabel)
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
	case ConfigAudit:
		return &v1alpha1.ConfigAuditReportList{}
	default:
		return nil
	}
}

type ResultDetails struct {
	Name      string
	Namespace string
	Status    string
}

type ToolCheckResult struct {
	ObjectType  string
	ID          string
	Remediation string
	Details     []ResultDetails
}

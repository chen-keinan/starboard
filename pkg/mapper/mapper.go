package mapper

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

const (
	ID     = "id"
	Status = "Status"
)

type Mapper interface {
	MapReportDataToMap(objList client.ObjectList, idsToMatch []string) []map[string]CheckDetails
}

type kubeBench struct {
}

type configAudit struct {
}

func ByTool(tool string) Mapper {
	switch tool {
	case "kube-bench":
		return &kubeBench{}
	case "config-audit":
		return &configAudit{}
	}
	// tool is not supported
	return nil
}

type CheckDetails struct {
	ID          string
	Status      string
	Remediation string
}

func (kb kubeBench) MapReportDataToMap(objList client.ObjectList, idsToMatch []string) []map[string]CheckDetails {
	objectsMap := make([]map[string]CheckDetails, 0)
	cb := objList.(*v1alpha1.CISKubeBenchReportList)
OUTER:
	for _, id := range idsToMatch {
		for _, item := range cb.Items {
			for _, section := range item.Report.Sections {
				for _, test := range section.Tests {
					checkMap := make(map[string]CheckDetails)
					for _, res := range test.Results {
						if id != res.TestNumber {
							continue
						}
						checkMap[res.TestNumber] = CheckDetails{ID: res.TestNumber, Status: strings.ToLower(res.Status), Remediation: res.Remediation}
						objectsMap = append(objectsMap, checkMap)
						continue OUTER
					}
				}
			}
		}
	}
	return objectsMap
}

func (ac configAudit) MapReportDataToMap(objList client.ObjectList, idsToMatch []string) []map[string]CheckDetails {
	acb := objList.(*v1alpha1.ConfigAuditReportList)
	objectsMap := make([]map[string]CheckDetails, 0)
OUTER:
	for _, id := range idsToMatch {
		for _, item := range acb.Items {
			for _, check := range item.Report.Checks {
				if id != check.ID {
					continue
				}
				checkMap := make(map[string]CheckDetails)
				status := "fail"
				if check.Success {
					status = "pass"
				}
				checkMap[check.ID] = CheckDetails{ID: check.ID, Status: status, Remediation: check.Remediation}
				objectsMap = append(objectsMap, checkMap)
				continue OUTER
			}
		}
	}
	return objectsMap
}

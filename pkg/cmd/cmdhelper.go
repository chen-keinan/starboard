package cmd

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetResourceListByType(reportName string, cli client.Client) (client.ObjectList, error) {
	objList := getObjListByName(reportName)
	err := cli.List(context.Background(), objList)
	if err != nil {
		return nil, fmt.Errorf("failed to find report resource %s", reportName)
	}
	return objList, nil
}

func getObjListByName(reportName string) client.ObjectList {
	switch reportName {
	case "CISKubeBenchReport":
		return &v1alpha1.CISKubeBenchReportList{}
	case "ConfigAuditReport":
		return &v1alpha1.ConfigAuditReportList{}
	default:
		return nil
	}
}

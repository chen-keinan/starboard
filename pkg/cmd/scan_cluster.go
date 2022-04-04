package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewScanClusterCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: kubeBenchCmdShort,
		RunE:  ScanForClusterReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanForClusterReports(cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return fmt.Errorf("failed to create kubeConfig: %w", err)
		}
		scheme := starboard.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		err = scanCisBench(cmd, args, cf)
		if err != nil {
			return err
		}
		objList, err := GetResourceListByType("CISKubeBenchReport", kubeClient)
		list := objList.(*v1alpha1.CISKubeBenchReportList)
		b, err := json.Marshal(&list)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
}

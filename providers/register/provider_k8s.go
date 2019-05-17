// +build k8s_provider

package register

import (

	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"github.com/virtual-kubelet/virtual-kubelet/providers/k8s"
)

func init() {
	register("k8s", initK8s)
}

func initK8s(cfg InitConfig) (providers.Provider, error) {

	return k8s.NewK8SProvider(
		cfg.ConfigPath,
		cfg.ResourceManager,
		cfg.NodeName,
		cfg.OperatingSystem,
		cfg.DaemonPort,)
}

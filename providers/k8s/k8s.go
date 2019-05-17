package k8s

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"bytes"

	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"k8s.io/api/core/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
        "k8s.io/client-go/tools/clientcmd"
	stats "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
//	"k8s.io/client-go/tools/clientcmd/api"
//	"k8s.io/client-go/rest/watch"
//	"k8s.io/client-go/1.4/kubernetes"
//	"k8s.io/client-go/1.4/pkg/api"
//	"k8s.io/client-go/1.4/tools/clientcmd"
)

type k8sProvider struct {
        QTSk8sClient	   *kubernetes.Clientset
	resourceManager    *manager.ResourceManager
	nodeName	   string
	operatingSystem    string
	cpu                string
	memory             string
	pods               string
	InternalIP	   string
	daemonEndpointPort int32
}

// NewK8SProvider creates a new K8SProvider.
func NewK8SProvider(config string, rm *manager.ResourceManager, nodeName string, operatingSystem string, daemonEndpointPort int32) (*k8sProvider, error) {
	var p k8sProvider
	var err error

	configK8s, err := clientcmd.BuildConfigFromFlags("", "/root/.kube2/config")
	if err != nil {
		log.Println(err)
		return nil, nil
        }
        clientset, _:= kubernetes.NewForConfig(configK8s)
//	pods, _:= clientset.Core().Pods("default").List(metav1.ListOptions{})
//	log.Println("There are %d pods in the cluster\n", len(pods.Items))

	p.QTSk8sClient = clientset
	p.resourceManager = rm

	// Set sane defaults for Capacity in case config is not supplied
	p.cpu = "20"
	p.memory = "100Gi"
	p.pods = "5"

	p.InternalIP = "192.168.80.82"
	p.operatingSystem = "Linux"
	p.nodeName = nodeName
	p.daemonEndpointPort = daemonEndpointPort

	return &p, err
}

// GetPod returns a pod by name that is running inside k8s
// returns nil if a pod by that name is not found.
func (p *k8sProvider) GetPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
//	log.Println("=================GetPod=================")

	if strings.Contains(name, "kube-proxy") {
		pods, _ := p.QTSk8sClient.Core().Pods(namespace).List(metav1.ListOptions{})
		for _, pod := range pods.Items {
			c1 := pod.Name[:len(pod.Name)-6]
			c2 := name[:len(name)-6]
			if c1 == c2 {
				name = pod.Name
				break
			}
		}
	}

	pod, err := p.QTSk8sClient.Core().Pods(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		log.Println(err)
		return nil, err
	}
/*
	log.Println("=================GetContainerLogs=================")
        req := p.QTSk8sClient.Core().Pods(namespace).GetLogs(name, &v1.PodLogOptions{})
        if req == nil {
		log.Println("req = nil")
        }
        podLogs, err := req.Stream()
        if err != nil {
		log.Println(err)
        }
        defer podLogs.Close()

        buf := new(bytes.Buffer)
        _, err = io.Copy(buf, podLogs)
        if err != nil {
		log.Println(err)
        }

        str := buf.String()
	log.Println(str)
	log.Println("=================GetContainerLogs=================")
*/
	return pod, nil
}

// GetPods returns a list of all pods known to be running within k8s.
func (p *k8sProvider) GetPods(ctx context.Context) ([]*v1.Pod, error) {
//	log.Println("=================GetPods=================")
	pods, err := p.QTSk8sClient.Core().Pods("default").List(metav1.ListOptions{})
	if err != nil {
                log.Println(err)
        }

	var result []*v1.Pod

	for _, pod := range pods.Items {
		result = append(result, &pod)
	}
	return result, nil
}

// CreatePod accepts a Pod definition and creates
// an Zun deployment
func (p *k8sProvider) CreatePod(ctx context.Context, pod *v1.Pod) error {
//////////////////////////////////////////////////////////////////
/*
	req := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "nginx",
					Image: "nginx",
				},
			},
		},
	}

	resp, _ := p.QTSk8sClient.Core().Pods("default").Create(req)

	fmt.Printf("Pod created: %s", resp)
*/
//////////////////////////////////////////////////////////////////

	log.Println("=================CreatePod=================")

	if strings.Contains(pod.ObjectMeta.Name ,"kube-proxy") {
		pod.ObjectMeta.Namespace = "default"
		return nil
	}
	namespace := pod.ObjectMeta.Namespace

	var defaultToken string
	// Get Secret List
	sList := p.ListSecret(ctx, namespace)
	// Change ResourceVersion
	pod.ObjectMeta.ResourceVersion = "0"
	// Without select Node
	pod.Spec.NodeName = ""
	// Change the volume's secret
	for index, _ := range pod.Spec.Volumes {
		n := pod.Spec.Volumes[index].Name
		for _, s := range sList {
			c1 := n[:len(n)-6]	//default-token-xxxxx from client
			c2 := s[:len(s)-6]	//default-token-xxxxx from provider
			if c1 == c2 {
				defaultToken = s
				pod.Spec.Volumes[index].Name = defaultToken
				break
			}
		}
//		pod.Spec.Volumes[index].Name = "default-token-8nb6w"	// temp secret

		if pod.Spec.Volumes[index].VolumeSource.Secret != nil {
			n := pod.Spec.Volumes[index].VolumeSource.Secret.SecretName
			for _, s := range sList {
				c1 := n[:len(n)-6]      //default-token-xxxxx from client
				c2 := s[:len(s)-6]      //default-token-xxxxx from provider
				if c1 == c2 {
					defaultToken = s
					pod.Spec.Volumes[index].VolumeSource.Secret.SecretName = defaultToken
					break
				}
			}
		}

	}

	for index, _ := range pod.Spec.Containers {
		for index2, _ := range pod.Spec.Containers[index].VolumeMounts {
			n := pod.Spec.Containers[index].VolumeMounts[index2].Name
			c1 := n[:len(n)-6]
			c2 := defaultToken[:len(defaultToken)-6]
			if c1 == c2 {
				pod.Spec.Containers[index].VolumeMounts[index2].Name = defaultToken
			}
		}
	}

/*
	log.Println("-----------------------------------------------------------")
	log.Println(pod.Spec.Volumes)
	log.Println(pod.Spec.InitContainers)
	log.Println(pod.Spec.Containers)
	log.Println("######################")
	log.Println(pod.Spec.Containers[0].VolumeDevices)
	log.Println(pod.Spec.Containers[0].VolumeMounts)
	log.Println("######################")
	log.Println(pod.Spec.RestartPolicy)
	log.Println(pod.Spec.DNSPolicy)
	log.Println(pod.Spec.NodeSelector)
	log.Println(pod.Spec.ServiceAccountName)
	log.Println(pod.Spec.DeprecatedServiceAccount)
	log.Println(pod.Spec.AutomountServiceAccountToken)
	log.Println(pod.Spec.SecurityContext)
	log.Println(pod.Spec.ImagePullSecrets)
	log.Println(pod.Spec.Hostname)
	log.Println(pod.Spec.Subdomain)
	log.Println(pod.Spec.Affinity)
	log.Println(pod.Spec.SchedulerName)
	log.Println(pod.Spec.Tolerations)
	log.Println(pod.Spec.HostAliases)
	log.Println(pod.Spec.PriorityClassName)
	log.Println(pod.Spec.Priority)
	log.Println(pod.Spec.DNSConfig)
	log.Println(pod.Spec.ReadinessGates)
	log.Println(pod.Spec.RuntimeClassName)
	log.Println("-----------------------------------------------------------")
*/
/*
	pod.Spec.PriorityClassName = ""
	pod.Spec.Priority = nil
	pod.Spec.Tolerations = nil
	pod.Spec.Affinity = nil
	pod.ObjectMeta.Annotations = nil
	pod.ObjectMeta.OwnerReferences = nil
*/

	_, err := p.QTSk8sClient.Core().Pods(namespace).Create(pod)
	if err != nil {
		log.Println("Create Error : ")
                log.Println(err)
        }

	return nil
}

func (p *k8sProvider) getContainers(ctx context.Context, pod *v1.Pod) ([]v1.Container, error) {
	log.Println("=================getContainers=================")
	results := pod.Spec.Containers
	return results, nil
}

// ExecInContainer executes a command in a container in the pod, copying data
// between in/out/err and the container's stdin/stdout/stderr.
func (p *k8sProvider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach providers.AttachIO) error {
	log.Printf("receive ExecInContainer")
	return nil
}

// GetPodStatus returns the status of a pod by name that is running inside Zun
// returns nil if a pod by that name is not found.
func (p *k8sProvider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {
	log.Println("=================GetPodStatus=================")
	pod, err := p.GetPod(ctx, namespace, name)

	if err != nil {
                return nil, err
        }

        if pod == nil {
                return nil, nil
        }

	return &pod.Status, nil
}

func (p *k8sProvider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts providers.ContainerLogOpts) (io.ReadCloser, error) {
	log.Println("=================GetContainerLogs=================")
	req := p.QTSk8sClient.Core().Pods(namespace).GetLogs(podName, &v1.PodLogOptions{})
	if req == nil {
                return ioutil.NopCloser(strings.NewReader("Req is nil")), nil
        }
	podLogs, err := req.Stream()
	if err != nil {
		return ioutil.NopCloser(strings.NewReader("error in opening stream")), err
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return ioutil.NopCloser(strings.NewReader("Req is nil")), err
	}
	str := buf.String()

	return ioutil.NopCloser(strings.NewReader(str)), nil
}

// NodeConditions returns a list of conditions (Ready, OutOfDisk, etc), for updates to the node status
// within Kubernetes.
func (p *k8sProvider) NodeConditions(ctx context.Context) []v1.NodeCondition {
	// TODO: Make these dynamic and augment with custom K8S specific conditions of interest
	return []v1.NodeCondition{
                {
                        Type:               v1.NodeReady,
                        Status:             v1.ConditionTrue,
                        LastHeartbeatTime:  metav1.Now(),
                        LastTransitionTime: metav1.Now(),
                        Reason:             "KubeletReady",
                        Message:            "kubelet is ready.",
                },
                {
                        Type:               v1.NodeOutOfDisk,
                        Status:             v1.ConditionFalse,
                        LastHeartbeatTime:  metav1.Now(),
                        LastTransitionTime: metav1.Now(),
                        Reason:             "KubeletHasSufficientDisk",
                        Message:            "kubelet has sufficient disk space available",
                },
                {
                        Type:               v1.NodeMemoryPressure,
                        Status:             v1.ConditionFalse,
                        LastHeartbeatTime:  metav1.Now(),
                        LastTransitionTime: metav1.Now(),
                        Reason:             "KubeletHasSufficientMemory",
                        Message:            "kubelet has sufficient memory available",
                },
                {
                        Type:               v1.NodeDiskPressure,
                        Status:             v1.ConditionFalse,
                        LastHeartbeatTime:  metav1.Now(),
                        LastTransitionTime: metav1.Now(),
                        Reason:             "KubeletHasNoDiskPressure",
                        Message:            "kubelet has no disk pressure",
                },
                {
                        Type:               v1.NodeNetworkUnavailable,
                        Status:             v1.ConditionFalse,
                        LastHeartbeatTime:  metav1.Now(),
                        LastTransitionTime: metav1.Now(),
                        Reason:             "RouteCreated",
                        Message:            "RouteController created a route",
                },
        }
}

// NodeAddresses returns a list of addresses for the node status
// within Kubernetes.
func (p *k8sProvider) NodeAddresses(ctx context.Context) []v1.NodeAddress {
	var result []v1.NodeAddress
	result = append(result, v1.NodeAddress {
				Type: v1.NodeInternalIP,
				Address: "192.168.80.82",
			})
	return result
}

// NodeDaemonEndpoints returns NodeDaemonEndpoints for the node status
// within Kubernetes.
func (p *k8sProvider) NodeDaemonEndpoints(ctx context.Context) *v1.NodeDaemonEndpoints {
	return &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{
			Port: p.daemonEndpointPort,
		},
	}
}

// OperatingSystem returns the operating system for this provider.
// This is a noop to default to Linux for now.
func (p *k8sProvider) OperatingSystem() string {
	return p.operatingSystem;
}


// UpdatePod is a noop, Zun currently does not support live updates of a pod.
func (p *k8sProvider) UpdatePod(ctx context.Context, pod *v1.Pod) error {
	log.Println("=================UpdatePod=================")
	return nil
}

// DeletePod deletes the specified pod out of Zun.
func (p *k8sProvider) DeletePod(ctx context.Context, pod *v1.Pod) error {
	log.Println("=================DeletePod=================")
	namespace := pod.ObjectMeta.Namespace
	name := pod.ObjectMeta.Name
	if name == "vk" {
		return nil
	}
	result := p.QTSk8sClient.Core().Pods(namespace).Delete(name, &metav1.DeleteOptions{})
	if result != nil {
                log.Println(result)
        }

	return nil
}

// Capacity returns a resource list containing the capacity limits set for Zun.
func (p *k8sProvider) Capacity(ctx context.Context) v1.ResourceList {
	return v1.ResourceList{
		"cpu":    resource.MustParse(p.cpu),
		"memory": resource.MustParse(p.memory),
		"pods":   resource.MustParse(p.pods),
	}
}

func (p *k8sProvider) ListSecret(ctx context.Context, namespace string) []string{
	var result []string
	secrets, err := p.QTSk8sClient.Core().Secrets(namespace).List(metav1.ListOptions{})
	if err != nil {
		log.Println(err)
		return nil
	}
	for _, s := range secrets.Items {
		result = append(result, s.ObjectMeta.Name)
	}
	return result
}

func (p *k8sProvider) GetSecret(ctx context.Context, namespace string, name string) *v1.Secret{
	secret, err := p.QTSk8sClient.Core().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		log.Println(err)
	}
	return secret
}

func (p *k8sProvider)  GetStatsSummary(ctx context.Context) (summary *stats.Summary, err error) {
	log.Println("GetStatsSummary")
	return nil, nil
}

package kube

import (
	"fmt"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Clients struct {
	Kubernetes kubernetes.Interface
	Dynamic    dynamic.Interface
	Discovery  discovery.DiscoveryInterface
	PodExec    PodExecutor
}

type ConfigOptions struct {
	Kubeconfig string
	Context    string
	Timeout    time.Duration
}

func NewClients(options ConfigOptions) (*Clients, error) {
	config, err := loadConfig(options)
	if err != nil {
		return nil, err
	}

	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic Kubernetes client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create discovery client: %w", err)
	}

	return &Clients{
		Kubernetes: kubernetesClient,
		Dynamic:    dynamicClient,
		Discovery:  discoveryClient,
		PodExec:    NewPodExecutor(config, kubernetesClient),
	}, nil
}

func loadConfig(options ConfigOptions) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if options.Kubeconfig != "" {
		rules.ExplicitPath = options.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: options.Context}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	config.Timeout = options.Timeout
	config.UserAgent = "kubectl-dig"
	return config, nil
}

package kube

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type PodExecutor interface {
	Exec(ctx context.Context, namespace, pod, container string, command []string) (string, string, error)
}

type podExecutor struct {
	config *rest.Config
	client kubernetes.Interface
}

func NewPodExecutor(config *rest.Config, client kubernetes.Interface) PodExecutor {
	return &podExecutor{config: rest.CopyConfig(config), client: client}
}

func (executor *podExecutor) Exec(
	ctx context.Context,
	namespace string,
	pod string,
	container string,
	command []string,
) (string, string, error) {
	request := executor.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	spdyExecutor, err := remotecommand.NewSPDYExecutor(executor.config, "POST", request.URL())
	if err != nil {
		return "", "", fmt.Errorf("create pod executor: %w", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := spdyExecutor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("execute command in pod: %w", err)
	}
	return stdout.String(), stderr.String(), nil
}

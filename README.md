# kdig

`kdig` is a Go-based kubectl plugin for diagnosing common MetalLB and Prometheus problems. Build the executable as `kubectl-dig`; kubectl exposes it as `kubectl dig` when the executable is on `PATH`.

## Build and install

```bash
go build -o bin/kubectl-dig ./cmd/kubectl-dig
```

Copy `bin/kubectl-dig` (or `bin/kubectl-dig.exe` on Windows) to a directory on `PATH`, then verify discovery:

```bash
kubectl plugin list
kubectl dig --help
```

## Usage

Running the plugin without a subcommand prints help and does not contact the cluster:

```bash
kubectl dig
```

Choose the component to diagnose:

```bash
kubectl dig metallb --namespace metallb-system
kubectl dig prometheus --namespace monitoring
```

MetalLB BGP checks execute `vtysh` in each speaker's FRR container. The defaults are namespace `metallb-system` and container `frr`; both can be overridden:

```bash
kubectl dig metallb --namespace metallb-system --frr-container frr
```

The caller needs permission to list cluster resources and create `pods/exec` requests in the MetalLB namespace.

Add Prometheus API checks for readiness, unhealthy scrape targets, and failing rules:

```bash
kubectl port-forward -n monitoring svc/prometheus-operated 9090:9090
kubectl dig prometheus --prometheus-url http://127.0.0.1:9090
```

The default output is plain text. Machine-readable output is available with `--output json`. Exit code `0` means only informational findings, `1` means warnings were found, and `2` means at least one critical problem was found.

## Checks

MetalLB checks include:

- controller Deployment and speaker DaemonSet availability
- unhealthy, pending, or frequently restarting pods
- IPAddressPool, L2Advertisement, BGPAdvertisement, and BGPPeer configuration
- pending LoadBalancer services, missing address pools, and services without ready endpoints
- FRR BGP summaries, neighbor state, IPv4 routes, and per-neighbor advertised routes
- webhook endpoints and recent warning events

Prometheus checks include:

- server StatefulSet or Deployment availability and pod health
- service endpoints and persistent volume claims
- Prometheus Operator resources such as ServiceMonitor, PodMonitor, and PrometheusRule
- recent Prometheus-related warning events
- optional Prometheus API readiness, scrape target health, and rule health

The active kubeconfig and context are used by default. Override them with `--kubeconfig` and `--context`.

## Project layout

```text
cmd/kubectl-dig/        plugin executable entry point
pkg/cli/                root command assembly
pkg/cli/common/         shared flags, clients, and report output
pkg/cli/metallb/        MetalLB subcommand
pkg/cli/prometheus/     Prometheus subcommand
pkg/diagnostic/         findings, reports, output, and exit codes
pkg/kube/               Kubernetes clients and shared health checks
pkg/metallb/            MetalLB diagnostic rules
pkg/prometheus/         Prometheus and Prometheus API diagnostic rules
```

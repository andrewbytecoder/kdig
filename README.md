# kdig

`kdig` is a Go-based kubectl plugin for diagnosing Kubernetes Pods and common MetalLB, Prometheus, and Alertmanager problems. Build the executable as `kubectl-dig`; kubectl exposes it as `kubectl dig` when the executable is on `PATH`.

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
kubectl dig amtool --namespace monitoring
kubectl dig podinfo api-0 --namespace apps
kubectl dig netcap --namespace apps --pod api-0
```

Capture packets from a Pod network namespace directly to the current machine:

```bash
# Capture until Ctrl+C and save to ./api-0.pcap.
kubectl dig netcap -n apps --pod api-0

# Capture TCP port 443 for 60 seconds to a chosen local file.
kubectl dig netcap -n apps --pod api-0 \
  --protocol tcp --port 443 --duration 60s -w api-https.pcap

# Directional filters and a packet-count limit.
kubectl dig netcap -n apps --pod api-0 \
  --protocol udp --src-host 10.0.0.10 --dst-port 53 \
  --count 100 -w dns.pcap

# Additional tcpdump BPF expression.
kubectl dig netcap -n apps --pod api-0 \
  --filter 'tcp[tcpflags] & tcp-syn != 0' -w syn.pcap
```

`netcap` resolves the Pod network PID using the same CRI inspection as `podinfo`, runs `nsenter -t PID -n -- tcpdump` on the node, and streams pcap bytes over SSH directly into the local file. By default it runs until Ctrl+C; `--duration` enables automatic timeout and `--count` can stop after a packet count. The default output is `POD.pcap`; existing files are protected unless `--overwrite` is specified. Ctrl+C asks tcpdump to flush and preserves a partial pcap when a valid pcap header was received. The result reports the actual packet count parsed from the pcap file. A tcpdump message such as `snapshot length 262144 bytes` is only the maximum bytes retained per packet, not the amount captured. The node must provide `crictl`, `nsenter`, and `tcpdump`; GNU `timeout` is additionally required when `--duration` is used. The SSH account must have permission to inspect the runtime and capture packets.

Inspect a Pod and its node-side network namespace:

```bash
# Passwordless SSH as root using SSH Agent or a default private key.
kubectl dig podinfo api-0 -n apps

# Traverse every Pod in the namespace.
kubectl dig podinfo -n apps

# Explicit account and password.
kubectl dig podinfo api-0 -n apps --username admin --password 'secret'

# Explicit private key.
kubectl dig podinfo api-0 -n apps --identity-file ~/.ssh/id_ed25519
```

`podinfo` reads the Pod and Node from Kubernetes, SSHes to the node IP, maps every Pod container using `crictl ps -a -o json`, and extracts the network PID with `crictl inspect`. It prints a ready-to-run command such as `nsenter -t 4242 -n`. SSH defaults to user `root`, port `22`, and passwordless authentication. Host keys use OpenSSH-style `accept-new`: unknown keys are appended to `~/.ssh/known_hosts`, while changed fingerprints are rejected. Use `--insecure-skip-host-key` only in a controlled test environment. Supplying `--password` can expose the password through shell history or process inspection, so SSH Agent or `--identity-file` is preferred.

The `amtool` command defaults to StatefulSet `alertmanager-main`, container `alertmanager`, and URL `http://localhost:9093`. Override them when the deployment uses different names:

```bash
kubectl dig amtool \
  --namespace monitoring \
  --statefulset alertmanager-main \
  --container alertmanager \
  --alertmanager-url http://localhost:9093
```

The command discovers every StatefulSet replica, such as `alertmanager-main-0`, `alertmanager-main-1`, and `alertmanager-main-2`, then executes `amtool` in each pod. The caller needs `get/list` access to StatefulSets and Pods plus permission to create `pods/exec` requests.

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

Alertmanager `amtool` checks include:

- StatefulSet replica availability and pod health
- active alerts in JSON and extended output formats
- loaded configuration summaries and cross-replica consistency
- routing trees, active or pending silences, and cluster peer status
- differences in active alert counts between replicas

Pod information checks include:

- Pod name, phase, Pod IP, node name, and node IP
- app, init, and ephemeral container names and Kubernetes container IDs
- CRI container mapping and current runtime attempt
- each container's network namespace PID and namespace identity
- a ready-to-run `nsenter -t PID -n` command

Network capture supports:

- protocol filters for TCP, UDP, ICMP, ICMPv6, ARP, IPv4, and IPv6
- source/destination ports and hosts, packet count, interface, snap length, and duration
- additional quoted tcpdump BPF expressions with `--filter`
- direct local pcap streaming without storing a capture file on the Kubernetes node

The active kubeconfig and context are used by default. Override them with `--kubeconfig` and `--context`.

## Project layout

```text
cmd/kubectl-dig/        plugin executable entry point
pkg/cli/                root command assembly
pkg/cli/common/         shared flags, clients, and report output
pkg/cli/amtool/         Alertmanager amtool subcommand
pkg/cli/metallb/        MetalLB subcommand
pkg/cli/netcap/         Pod network capture subcommand
pkg/cli/podinfo/        Pod and network namespace subcommand
pkg/cli/prometheus/     Prometheus subcommand
pkg/diagnostic/         findings, reports, output, and exit codes
pkg/kube/               Kubernetes clients and shared health checks
pkg/amtool/             Alertmanager amtool diagnostic rules
pkg/metallb/            MetalLB diagnostic rules
pkg/netcap/             Network capture command and local pcap handling
pkg/podinfo/            Pod, SSH, CRI, and network namespace rules
pkg/prometheus/         Prometheus and Prometheus API diagnostic rules
```

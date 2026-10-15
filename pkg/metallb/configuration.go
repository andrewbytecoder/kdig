package metallb

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type configurationState struct {
	pools         map[string]struct{}
	peerAddresses []string
	bgpEnabled    bool
}

func (checker *Checker) checkConfiguration(ctx context.Context, report *diagnostic.Report) configurationState {
	state := configurationState{pools: make(map[string]struct{})}
	checker.checkCRDs(ctx, report)
	checker.checkAddressPools(ctx, report, &state)
	peers := checker.checkBGPPeers(ctx, report, &state)
	bgpAdvertisements := checker.checkAdvertisements(ctx, report, bgpResource, "BGPAdvertisement", "bgp-configuration")
	l2Advertisements := checker.checkAdvertisements(ctx, report, l2Resource, "L2Advertisement", "l2-configuration")

	state.bgpEnabled = peers > 0 || bgpAdvertisements > 0
	if bgpAdvertisements == 0 && l2Advertisements == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "configuration",
			Summary:    "No L2Advertisement or BGPAdvertisement is configured",
			Suggestion: "Create an advertisement matching the address pool and intended network mode.",
		})
	}
	if bgpAdvertisements > 0 && peers == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "bgp-configuration",
			Resource:   "bgpadvertisements.metallb.io",
			Summary:    "BGP advertisements exist but no BGPPeer was found",
			Suggestion: "Configure at least one BGPPeer or verify peer resources in this namespace.",
		})
	}
	return state
}

func (checker *Checker) checkCRDs(ctx context.Context, report *diagnostic.Report) {
	list, err := checker.clients.Dynamic.Resource(crdResource).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("crds", "list CustomResourceDefinitions", err))
		return
	}

	names := make([]string, 0)
	for _, item := range list.Items {
		if strings.HasSuffix(item.GetName(), ".metallb.io") {
			names = append(names, item.GetName())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "crds",
			Summary:    "No MetalLB CustomResourceDefinitions were found",
			Suggestion: "Install or repair the MetalLB CRDs before applying MetalLB configuration.",
		})
		return
	}
	for _, name := range names {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "crds",
			Resource: "customresourcedefinition/" + name,
			Summary:  "MetalLB CRD is installed",
		})
	}
}

func (checker *Checker) checkAddressPools(ctx context.Context, report *diagnostic.Report, state *configurationState) {
	list, err := checker.clients.Dynamic.Resource(addressPoolResource).Namespace(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "address-pools",
			Resource:   "ipaddresspools.metallb.io",
			Summary:    "Cannot read MetalLB IPAddressPool resources",
			Detail:     err.Error(),
			Suggestion: "Verify MetalLB CRDs are installed and RBAC allows listing IPAddressPools.",
		})
		return
	}
	if len(list.Items) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "address-pools",
			Resource:   "ipaddresspools.metallb.io",
			Summary:    "No IPAddressPool is configured",
			Suggestion: "Create an IPAddressPool containing addresses reachable on the local network.",
		})
		return
	}
	for _, pool := range list.Items {
		state.pools[pool.GetName()] = struct{}{}
		addresses := nestedValue(&pool, "spec", "addresses")
		detail := detailLines(
			"Addresses", addresses,
			"Auto assign", nestedValue(&pool, "spec", "autoAssign"),
			"Avoid buggy IPs", nestedValue(&pool, "spec", "avoidBuggyIPs"),
			"Assigned IPv4", nestedValue(&pool, "status", "assignedIPv4"),
			"Available IPv4", nestedValue(&pool, "status", "availableIPv4"),
			"Assigned IPv6", nestedValue(&pool, "status", "assignedIPv6"),
			"Available IPv6", nestedValue(&pool, "status", "availableIPv6"),
		)
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "address-pools",
			Resource: diagnostic.Resource("ipaddresspool", checker.options.Namespace, pool.GetName()),
			Summary:  "IPAddressPool is configured: " + addresses,
			Detail:   detail,
		})
	}
}

func (checker *Checker) checkBGPPeers(ctx context.Context, report *diagnostic.Report, state *configurationState) int {
	list, ok := checker.listOptionalResources(ctx, report, bgpPeerResource, "bgp-configuration")
	if !ok {
		return 0
	}
	if len(list) == 0 {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "bgp-configuration",
			Resource: "bgppeers.metallb.io",
			Summary:  "No BGPPeer is configured",
		})
		return 0
	}
	for _, peer := range list {
		address := nestedValue(&peer, "spec", "peerAddress")
		if address != "-" {
			state.peerAddresses = append(state.peerAddresses, address)
		}
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "bgp-configuration",
			Resource: diagnostic.Resource("bgppeer", checker.options.Namespace, peer.GetName()),
			Summary:  fmt.Sprintf("Peer %s, peer ASN %s, local ASN %s", address, nestedValue(&peer, "spec", "peerASN"), nestedValue(&peer, "spec", "myASN")),
			Detail: detailLines(
				"Node selectors", nestedValue(&peer, "spec", "nodeSelectors"),
				"Source address", nestedValue(&peer, "spec", "sourceAddress"),
				"Router ID", nestedValue(&peer, "spec", "routerID"),
				"VRF", nestedValue(&peer, "spec", "vrf"),
			),
		})
	}
	return len(list)
}

func (checker *Checker) checkAdvertisements(
	ctx context.Context,
	report *diagnostic.Report,
	resource schema.GroupVersionResource,
	kind string,
	check string,
) int {
	list, ok := checker.listOptionalResources(ctx, report, resource, check)
	if !ok {
		return 0
	}
	for _, advertisement := range list {
		details := []string{
			"Address pools", nestedValue(&advertisement, "spec", "ipAddressPools"),
			"Pool selectors", nestedValue(&advertisement, "spec", "ipAddressPoolSelectors"),
			"Node selectors", nestedValue(&advertisement, "spec", "nodeSelectors"),
		}
		if kind == "BGPAdvertisement" {
			details = append(details,
				"Peers", nestedValue(&advertisement, "spec", "peers"),
				"Communities", nestedValue(&advertisement, "spec", "communities"),
				"Local preference", nestedValue(&advertisement, "spec", "localPref"),
			)
		} else {
			details = append(details, "Interfaces", nestedValue(&advertisement, "spec", "interfaces"))
		}
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    check,
			Resource: diagnostic.Resource(kind, checker.options.Namespace, advertisement.GetName()),
			Summary:  kind + " is configured",
			Detail:   detailLines(details...),
		})
	}
	return len(list)
}

func (checker *Checker) listOptionalResources(
	ctx context.Context,
	report *diagnostic.Report,
	resource schema.GroupVersionResource,
	check string,
) ([]unstructured.Unstructured, bool) {
	list, err := checker.clients.Dynamic.Resource(resource).Namespace(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			report.Add(apiFailure(check, "list "+resource.Resource+"."+resource.Group, err))
		}
		return nil, false
	}
	return list.Items, true
}

func nestedValue(object *unstructured.Unstructured, fields ...string) string {
	value, found, err := unstructured.NestedFieldNoCopy(object.Object, fields...)
	if err != nil || !found || value == nil {
		return "-"
	}
	if text, ok := value.(string); ok {
		if text == "" {
			return "-"
		}
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

func detailLines(values ...string) string {
	lines := make([]string, 0, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		if values[index+1] == "" || values[index+1] == "-" {
			continue
		}
		lines = append(lines, values[index]+": "+values[index+1])
	}
	return strings.Join(lines, "\n")
}

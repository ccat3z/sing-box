package option

import (
	"fmt"

	"github.com/sagernet/sing/common/json"
)

// NebulaOutboundOptions configures a nebula [github.com/slackhq/nebula] tunnel as
// an outbound. The field names mirror nebula's own configuration keys
// (static_host_map, lighthouse, punchy, relay) so that an existing nebula YAML
// maps over directly. The overlay address (VPN IP + mask) is not configured
// here — it is derived from the node certificate by nebula itself.
type NebulaOutboundOptions struct {
	PKI           NebulaPKI           `json:"pki"`
	StaticHostMap map[string][]string `json:"static_host_map,omitempty"`
	Lighthouse    NebulaLighthouse    `json:"lighthouse,omitempty"`
	Relay         *NebulaRelay        `json:"relay,omitempty"`
	UnsafeRoutes  []NebulaUnsafeRoute `json:"unsafe_routes,omitempty"`
	MTU           uint32              `json:"mtu,omitempty"`
	DialerOptions
}

// NebulaPKI mirrors nebula's pki block (ca / cert / key). The cert embeds the
// node's overlay address, which nebula derives the tunnel CIDR from.
type NebulaPKI struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// NebulaLighthouse mirrors nebula's lighthouse.hosts / lighthouse.am_lighthouse keys.
type NebulaLighthouse struct {
	Hosts       []string `json:"hosts,omitempty"`
	AmLighthouse bool    `json:"am_lighthouse,omitempty"`
}

// NebulaRelay mirrors nebula's relay block.
type NebulaRelay struct {
	UseRelays bool     `json:"use_relays,omitempty"`
	Relays    []string `json:"relays,omitempty"`
	AmRelay   bool     `json:"am_relay,omitempty"`
}

// NebulaUnsafeRoute mirrors one entry of nebula's tun.unsafe_routes: route a
// non-overlay subnet through a gateway peer (the peer then forwards the packet
// unchanged, so its certificate must list the subnet and its OS must route the
// reply back). mtu/metric/install are accepted for native-config paste
// compatibility but ignored: they only matter when nebula installs OS routes
// for a kernel TUN device, which the userspace outbound has none of.
type NebulaUnsafeRoute struct {
	Route   string         `json:"route"`
	Via     NebulaRouteVia `json:"via"`
	MTU     uint32         `json:"mtu,omitempty"`
	Metric  int            `json:"metric,omitempty"`
	Install *bool          `json:"install,omitempty"`
}

// NebulaRouteGateway is one entry of the via gateway list (ECMP form).
type NebulaRouteGateway struct {
	Gateway string `json:"gateway"`
	Weight  int    `json:"weight,omitempty"`
}

// NebulaRouteVia is nebula's via union: a bare gateway IP string (weight 1) or
// a list of {gateway, weight} objects. The two forms match native nebula
// exactly — nothing else is accepted.
type NebulaRouteVia struct {
	// Single records that the JSON was a bare string so MarshalJSON round-trips.
	Single    bool
	Gateways  []NebulaRouteGateway
}

func (v *NebulaRouteVia) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		v.Single = true
		v.Gateways = []NebulaRouteGateway{{Gateway: single}}
		return nil
	}
	var gateways []NebulaRouteGateway
	if err := json.Unmarshal(data, &gateways); err != nil {
		return fmt.Errorf("via must be a gateway IP string or a list of {gateway, weight} objects: %w", err)
	}
	v.Gateways = gateways
	return nil
}

func (v NebulaRouteVia) MarshalJSON() ([]byte, error) {
	if v.Single {
		if len(v.Gateways) != 1 {
			return nil, fmt.Errorf("via: single form requires exactly one gateway")
		}
		return json.Marshal(v.Gateways[0].Gateway)
	}
	return json.Marshal(v.Gateways)
}

package option

import (
	"net/netip"
)

// NebulaOutboundOptions configures a nebula [github.com/slackhq/nebula] tunnel as
// an outbound. The field names mirror nebula's own configuration keys
// (static_host_map, lighthouse, punchy, relay) so that an existing nebula YAML
// maps over directly.
type NebulaOutboundOptions struct {
	LocalAddress  netip.Prefix        `json:"local_address"`
	PrivateKey    string              `json:"private_key"`
	Certificate   string              `json:"certificate"`
	CA            string              `json:"ca"`
	StaticHostMap map[string][]string `json:"static_host_map,omitempty"`
	Lighthouse    NebulaLighthouse    `json:"lighthouse,omitempty"`
	Relay         *NebulaRelay        `json:"relay,omitempty"`
	MTU           uint32              `json:"mtu,omitempty"`
	DialerOptions
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

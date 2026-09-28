package option

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

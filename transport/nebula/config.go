package nebula

import (
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"

	"github.com/sagernet/sing-box/option"
)

// buildConfig translates the sing-box option struct into nebula's config.C,
// populating the public Settings map directly (no YAML round-trip). The keys
// mirror a standard nebula config.yaml, so any existing nebula config maps over.
func buildConfig(opts option.NebulaOutboundOptions) (*config.C, error) {
	c := config.NewC(logrus.New())

	c.Settings["pki"] = map[interface{}]interface{}{
		"ca":   opts.PKI.CA,
		"cert": opts.PKI.Cert,
		"key":  opts.PKI.Key,
	}

	// static_host_map: { "10.35.99.1": ["host:port", ...] }
	staticHostMap := map[interface{}]interface{}{}
	for vpnIP, endpoints := range opts.StaticHostMap {
		ifaceEndpoints := make([]interface{}, len(endpoints))
		for i, ep := range endpoints {
			ifaceEndpoints[i] = ep
		}
		staticHostMap[vpnIP] = ifaceEndpoints
	}
	c.Settings["static_host_map"] = staticHostMap

	lighthouse := map[interface{}]interface{}{
		"hosts":        toStringSlice(opts.Lighthouse.Hosts),
		"am_lighthouse": opts.Lighthouse.AmLighthouse,
	}
	c.Settings["lighthouse"] = lighthouse

	// punchy is always on: NAT hole-punching is required for host-to-host
	// routing (lighthouse discovery, relay, roaming).
	c.Settings["punchy"] = map[interface{}]interface{}{
		"punch": true,
	}

	if opts.Relay != nil {
		c.Settings["relay"] = map[interface{}]interface{}{
			"use_relays": opts.Relay.UseRelays,
			"relays":     toStringSlice(opts.Relay.Relays),
			"am_relay":   opts.Relay.AmRelay,
		}
	}

	// Allow-all firewall: the test topology and the desired use case (reach any
	// overlay peer's services) don't need nebula-side filtering.
	c.Settings["firewall"] = map[interface{}]interface{}{
		"outbound": []interface{}{
			map[interface{}]interface{}{"port": "any", "proto": "any", "host": "any"},
		},
		"inbound": []interface{}{
			map[interface{}]interface{}{"port": "any", "proto": "any", "host": "any"},
		},
	}

	// A (unused) tun device name; our custom overlay.Device ignores it but nebula
	// expects the key to exist in some code paths.
	c.Settings["tun"] = map[interface{}]interface{}{"dev": "faketun0"}

	// Single-queue: our device is not multiqueue.
	c.Settings["routines"] = 1

	return c, nil
}

func toStringSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

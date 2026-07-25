package nebula

import (
	"log/slog"

	"github.com/slackhq/nebula/config"

	"github.com/sagernet/sing-box/option"
)

// buildConfig translates the sing-box option struct into nebula's config.C,
// populating the public Settings map directly (no YAML round-trip). The keys
// mirror a standard nebula config.yaml, so any existing nebula config maps over.
//
// NOTE: nebula v1.11.0's config.Get traverses Settings expecting map[string]any
// (it type-asserts to map[string]any at each path segment). The older
// map[interface{}]interface{} form (viper/YAML style, accepted by v1.9.5) now
// silently fails the assertion and reads back as unset — so all nested maps
// here must be map[string]any.
func buildConfig(opts option.NebulaOutboundOptions, logger *slog.Logger) (*config.C, error) {
	c := config.NewC(logger)

	c.Settings["pki"] = map[string]any{
		"ca":   opts.PKI.CA,
		"cert": opts.PKI.Cert,
		"key":  opts.PKI.Key,
	}

	// static_host_map: { "10.35.99.1": ["host:port", ...] }
	staticHostMap := map[string]any{}
	for vpnIP, endpoints := range opts.StaticHostMap {
		ifaceEndpoints := make([]any, len(endpoints))
		for i, ep := range endpoints {
			ifaceEndpoints[i] = ep
		}
		staticHostMap[vpnIP] = ifaceEndpoints
	}
	c.Settings["static_host_map"] = staticHostMap

	lighthouse := map[string]any{
		"hosts":         toStringSlice(opts.Lighthouse.Hosts),
		"am_lighthouse": opts.Lighthouse.AmLighthouse,
	}
	c.Settings["lighthouse"] = lighthouse

	// punchy is always on: NAT hole-punching is required for host-to-host
	// routing (lighthouse discovery, relay, roaming).
	c.Settings["punchy"] = map[string]any{
		"punch": true,
	}

	if opts.Relay != nil {
		c.Settings["relay"] = map[string]any{
			"use_relays": opts.Relay.UseRelays,
			"relays":     toStringSlice(opts.Relay.Relays),
			"am_relay":   opts.Relay.AmRelay,
		}
	}

	// Allow-all firewall: the test topology and the desired use case (reach any
	// overlay peer's services) don't need nebula-side filtering.
	c.Settings["firewall"] = map[string]any{
		"outbound": []any{
			map[string]any{"port": "any", "proto": "any", "host": "any"},
		},
		"inbound": []any{
			map[string]any{"port": "any", "proto": "any", "host": "any"},
		},
	}

	// A (unused) tun device name; our custom overlay.Device ignores it but nebula
	// expects the key to exist in some code paths.
	c.Settings["tun"] = map[string]any{"dev": "faketun0"}

	// Single-queue: our device is not multiqueue.
	c.Settings["routines"] = 1

	return c, nil
}

func toStringSlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

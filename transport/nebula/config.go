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
	// expects the key to exist in some code paths. unsafe_routes is emitted in
	// nebula's native format and consumed by overlay.ParseUnsafeRoutes inside the
	// device factory. All numeric values must be Go ints: nebula's parser
	// type-asserts .(int) and panics on the float64 a raw JSON passthrough yields.
	tunSettings := map[string]any{"dev": "faketun0"}
	if len(opts.UnsafeRoutes) > 0 {
		entries := make([]any, len(opts.UnsafeRoutes))
		for i, r := range opts.UnsafeRoutes {
			m := map[string]any{
				"route": r.Route,
				"via":   nebulaViaValue(r.Via),
			}
			if r.MTU != 0 {
				m["mtu"] = int(r.MTU)
			}
			if r.Metric != 0 {
				m["metric"] = r.Metric
			}
			if r.Install != nil {
				m["install"] = *r.Install
			}
			entries[i] = m
		}
		tunSettings["unsafe_routes"] = entries
	}
	c.Settings["tun"] = tunSettings

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

// nebulaViaValue renders the via union back into nebula's native config shape:
// a bare string for the single-gateway form, otherwise a list of
// {gateway, weight} maps with int weights (asserted as int by nebula).
func nebulaViaValue(v option.NebulaRouteVia) any {
	if v.Single {
		return v.Gateways[0].Gateway
	}
	list := make([]any, len(v.Gateways))
	for i, g := range v.Gateways {
		weight := g.Weight
		if weight == 0 {
			weight = 1
		}
		list[i] = map[string]any{"gateway": g.Gateway, "weight": weight}
	}
	return list
}

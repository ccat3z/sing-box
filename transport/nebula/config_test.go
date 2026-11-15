package nebula

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sagernet/sing-box/option"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	require.NoError(t, err)
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return a
}

func tunSettings(t *testing.T, opts option.NebulaOutboundOptions) map[string]any {
	t.Helper()
	c, err := buildConfig(opts, slog.Default())
	require.NoError(t, err)
	tun, ok := c.Settings["tun"].(map[string]any)
	require.True(t, ok)
	return tun
}

func TestBuildConfigNoUnsafeRoutes(t *testing.T) {
	tun := tunSettings(t, option.NebulaOutboundOptions{})
	_, present := tun["unsafe_routes"]
	assert.False(t, present, "no unsafe_routes key when the option is empty")
}

func TestBuildConfigUnsafeRoutesSingleVia(t *testing.T) {
	tun := tunSettings(t, option.NebulaOutboundOptions{
		UnsafeRoutes: []option.NebulaUnsafeRoute{
			{Route: "10.36.0.0/24", Via: option.NebulaRouteVia{
				Single:   true,
				Gateways: []option.NebulaRouteGateway{{Gateway: "10.35.99.1"}},
			}},
		},
	})
	routes, ok := tun["unsafe_routes"].([]any)
	require.True(t, ok, "unsafe_routes is an array")
	require.Len(t, routes, 1)
	entry, ok := routes[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "10.36.0.0/24", entry["route"])
	// The single form must render as a bare string, not a one-element list.
	assert.Equal(t, "10.35.99.1", entry["via"])
}

func TestBuildConfigUnsafeRoutesGatewayList(t *testing.T) {
	tun := tunSettings(t, option.NebulaOutboundOptions{
		UnsafeRoutes: []option.NebulaUnsafeRoute{
			{
				Route:  "10.36.0.0/24",
				MTU:    1300,
				Metric: 100,
				Via: option.NebulaRouteVia{Gateways: []option.NebulaRouteGateway{
					{Gateway: "10.35.99.1", Weight: 1},
					{Gateway: "10.35.99.2", Weight: 2},
				}},
			},
		},
	})
	routes := tun["unsafe_routes"].([]any)
	entry := routes[0].(map[string]any)
	via, ok := entry["via"].([]any)
	require.True(t, ok, "list form via is an array")
	require.Len(t, via, 2)
	gw0 := via[0].(map[string]any)
	gw1 := via[1].(map[string]any)
	assert.Equal(t, "10.35.99.1", gw0["gateway"])
	assert.Equal(t, "10.35.99.2", gw1["gateway"])
	// nebula's parser asserts .(int); a float64 here would panic at start.
	assert.Equal(t, 1, gw0["weight"])
	assert.Equal(t, 2, gw1["weight"])
	assert.Equal(t, 1300, entry["mtu"])
	assert.Equal(t, 100, entry["metric"])
}

// TestBuildConfigUnsafeRoutesEndToEnd runs the built settings through nebula's
// own parser: the config we generate must be accepted and produce the expected
// gateways, including the ECMP bucket calculation done by MakeRouteTree.
func TestBuildConfigUnsafeRoutesEndToEnd(t *testing.T) {
	opts := option.NebulaOutboundOptions{
		UnsafeRoutes: []option.NebulaUnsafeRoute{
			{
				Route: "10.36.0.0/24",
				Via: option.NebulaRouteVia{Gateways: []option.NebulaRouteGateway{
					{Gateway: "10.35.99.1", Weight: 1},
					{Gateway: "10.35.99.2", Weight: 2},
				}},
			},
			{Route: "10.37.0.0/16", Via: option.NebulaRouteVia{
				Single:   true,
				Gateways: []option.NebulaRouteGateway{{Gateway: "10.35.99.1"}},
			}},
		},
	}
	c, err := buildConfig(opts, slog.Default())
	require.NoError(t, err)

	overlayNetwork := mustPrefix(t, "10.35.99.0/24")
	routes, err := overlay.ParseUnsafeRoutes(c, []netip.Prefix{overlayNetwork})
	require.NoError(t, err)
	require.Len(t, routes, 2)

	tree, err := overlay.MakeRouteTree(slog.Default(), routes, false)
	require.NoError(t, err)

	gws, ok := tree.Lookup(mustAddr(t, "10.36.0.7"))
	require.True(t, ok)
	require.Len(t, gws, 2)
	assert.NotEqual(t, routing.BucketNotCalculated, gws[0].BucketUpperBound(),
		"ECMP buckets must be calculated for BalancePacket")

	gws, ok = tree.Lookup(mustAddr(t, "10.37.1.1"))
	require.True(t, ok)
	require.Len(t, gws, 1)
}

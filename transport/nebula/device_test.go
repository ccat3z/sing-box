package nebula

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRoutes(t *testing.T, settings map[string]any, overlayNetwork string) []overlay.Route {
	t.Helper()
	c := config.NewC(slog.Default())
	c.Settings["tun"] = settings
	routes, err := overlay.ParseUnsafeRoutes(c, []netip.Prefix{mustPrefix(t, overlayNetwork)})
	require.NoError(t, err)
	return routes
}

// deviceFor builds a safeDevice from raw tun settings, exercising the same
// parse → MakeRouteTree path the endpoint's device factory uses.
func deviceFor(t *testing.T, settings map[string]any) *safeDevice {
	t.Helper()
	routes := testRoutes(t, settings, "10.35.99.0/24")
	dev, err := newSafeDevice(mustPrefix(t, "10.35.99.0/24"), slog.Default(), routes)
	require.NoError(t, err)
	return dev
}

func TestSafeDeviceRoutesForNoRoutes(t *testing.T) {
	dev := deviceFor(t, map[string]any{"dev": "faketun0"})
	assert.False(t, dev.hasRoutes, "no unsafe_routes configured")
	// Legacy fallback: gateway = the address itself (overlay destinations never
	// reach RoutesFor, this only preserves the old behavior for others).
	gws := dev.RoutesFor(mustAddr(t, "10.36.0.7"))
	require.Len(t, gws, 1)
	assert.Equal(t, mustAddr(t, "10.36.0.7"), gws[0].Addr())
}

func TestSafeDeviceRoutesForLongestPrefix(t *testing.T) {
	dev := deviceFor(t, map[string]any{
		"dev": "faketun0",
		"unsafe_routes": []any{
			map[string]any{"route": "10.36.0.0/16", "via": "10.35.99.1"},
			map[string]any{"route": "10.36.1.0/24", "via": "10.35.99.2"},
		},
	})
	gws := dev.RoutesFor(mustAddr(t, "10.36.1.9"))
	require.Len(t, gws, 1)
	assert.Equal(t, mustAddr(t, "10.35.99.2"), gws[0].Addr(), "/24 must beat /16")

	gws = dev.RoutesFor(mustAddr(t, "10.36.2.9"))
	require.Len(t, gws, 1)
	assert.Equal(t, mustAddr(t, "10.35.99.1"), gws[0].Addr())
}

func TestSafeDeviceRoutesForMiss(t *testing.T) {
	dev := deviceFor(t, map[string]any{
		"dev":          "faketun0",
		"unsafe_routes": []any{map[string]any{"route": "10.36.0.0/24", "via": "10.35.99.1"}},
	})
	// Configured but no match: native semantics — drop immediately.
	assert.Nil(t, dev.RoutesFor(mustAddr(t, "10.37.9.9")))
}

func TestSafeDeviceRoutesForECMP(t *testing.T) {
	dev := deviceFor(t, map[string]any{
		"dev": "faketun0",
		"unsafe_routes": []any{
			map[string]any{
				"route": "10.36.0.0/24",
				"via": []any{
					map[string]any{"gateway": "10.35.99.1", "weight": 1},
					map[string]any{"gateway": "10.35.99.2", "weight": 2},
				},
			},
		},
	})
	gws := dev.RoutesFor(mustAddr(t, "10.36.0.7"))
	require.Len(t, gws, 2)
	for i := range gws {
		assert.NotEqual(t, routing.BucketNotCalculated, gws[i].BucketUpperBound(),
			"ECMP buckets must be calculated for BalancePacket")
	}
}

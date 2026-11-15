package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeVia(t *testing.T, raw string) (NebulaRouteVia, error) {
	t.Helper()
	var opts struct {
		Via NebulaRouteVia `json:"via"`
	}
	err := json.Unmarshal([]byte(raw), &opts)
	return opts.Via, err
}

func TestNebulaRouteViaDecode(t *testing.T) {
	via, err := decodeVia(t, `{"via": "10.35.99.1"}`)
	require.NoError(t, err)
	assert.True(t, via.Single)
	require.Len(t, via.Gateways, 1)
	assert.Equal(t, "10.35.99.1", via.Gateways[0].Gateway)

	via, err = decodeVia(t, `{"via": [{"gateway": "10.35.99.1", "weight": 1}, {"gateway": "10.35.99.2", "weight": 2}]}`)
	require.NoError(t, err)
	assert.False(t, via.Single)
	require.Len(t, via.Gateways, 2)
	assert.Equal(t, "10.35.99.2", via.Gateways[1].Gateway)
	assert.Equal(t, 2, via.Gateways[1].Weight)

	// Native nebula accepts only the two forms above; so do we.
	_, err = decodeVia(t, `{"via": ["10.35.99.1", "10.35.99.2"]}`)
	assert.Error(t, err, "bare string list is not a native nebula form")
	_, err = decodeVia(t, `{"via": 42}`)
	assert.Error(t, err)
}

func TestNebulaRouteViaMarshalRoundTrip(t *testing.T) {
	marshaled, err := json.Marshal(map[string]any{
		"via": NebulaRouteVia{Single: true, Gateways: []NebulaRouteGateway{{Gateway: "10.35.99.1"}}},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"via": "10.35.99.1"}`, string(marshaled))
}

package nebula

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transportNebula "github.com/sagernet/sing-box/transport/nebula"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NebulaOutboundOptions](registry, C.TypeNebula, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	endpoint *transportNebula.Endpoint
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NebulaOutboundOptions) (adapter.Outbound, error) {
	endpoint, err := transportNebula.New(ctx, options)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:  outbound.NewAdapterWithDialerOptions(C.TypeNebula, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		endpoint: endpoint,
	}, nil
}

func (o *Outbound) Start() error {
	return o.endpoint.Start()
}

func (o *Outbound) Close() error {
	return o.endpoint.Close()
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.endpoint.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.endpoint.ListenPacket(ctx, destination)
}

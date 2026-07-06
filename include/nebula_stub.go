//go:build !with_nebula

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerNebulaOutbound(registry *outbound.Registry) {
	outbound.Register[option.NebulaOutboundOptions](registry, C.TypeNebula, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NebulaOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Nebula is not included in this build, rebuild with -tags with_nebula`)
	})
}

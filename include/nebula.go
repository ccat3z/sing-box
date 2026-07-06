//go:build with_nebula

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/nebula"
)

func registerNebulaOutbound(registry *outbound.Registry) {
	nebula.RegisterOutbound(registry)
}

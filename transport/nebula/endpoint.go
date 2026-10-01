package nebula

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	nebulaudp "github.com/slackhq/nebula/udp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const nicID = 1

// defaultMTU is nebula's default overlay MTU.
const defaultMTU = 1300

// Endpoint ties a running nebula tunnel (UserDevice mode, no kernel TUN) to a
// userspace gvisor netstack, exposing DialContext/ListenPacket over the overlay.
// It is the sing-box transport; protocol/nebula wraps it in an adapter.Outbound.
type Endpoint struct {
	opts        option.NebulaOutboundOptions
	cfg         *config.C
	logger      *slog.Logger
	outerDialer N.Dialer
	ctx         context.Context

	ctrl    *nebula.Control
	device  *safeDevice
	ipstack *stack.Stack
	linkEP  *channel.Endpoint

	mtu      uint32
	localIP  netip.Addr
	started  atomicStart
	closed   atomicClose
	closeCtx context.Context
	closeFn  context.CancelFunc

	// restartAccess serializes tunnel teardown/rebuild between Restart()'s
	// goroutine and Close(), and naturally coalesces interface-flap bursts
	// (each ResetNetwork round spawns a goroutine; they queue on this lock).
	restartAccess sync.Mutex
}

type atomicStart struct {
	once sync.Once
	err  error
	done bool
}

type atomicClose struct {
	once   sync.Once
	closed bool
}

// New constructs the endpoint WITHOUT binding any sockets. nebula.Main binds the
// outer UDP socket (via the device/udp factories) inside it, and that must run
// in Start() — not here — because on Android the dialer's interface-selection
// strategy (NetworkStrategyDefault) needs the VPN default interface to be
// detected first, which only happens after early startup. Constructing here used
// to race the interface monitor and fail with "no available network interface".
func New(ctx context.Context, opts option.NebulaOutboundOptions) (*Endpoint, error) {
	// nebula v1.11.0 uses log/slog; bridge its records into sing-box's log
	// package (→ logcat on Android). Built before buildConfig so config-parse
	// logs are also captured.
	logger := slog.New(&nebulaLogBridge{})

	cfg, err := buildConfig(opts, logger)
	if err != nil {
		return nil, err
	}

	// Outer-transport dialer: sing-box's N.Dialer, honoring DialerOptions
	// (bind_interface, detour, routing_mark, domain resolver, …). Constructing the
	// dialer does not open a socket — it only resolves bind/strategy config. The
	// actual UDP listen happens later, from Start().
	outerDialer, err := dialer.New(ctx, opts.DialerOptions, false)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}

	mtu := uint32(defaultMTU)
	if opts.MTU != 0 {
		mtu = opts.MTU
	}

	closeCtx, closeFn := context.WithCancel(ctx)
	return &Endpoint{
		ctx:         ctx,
		opts:        opts,
		cfg:         cfg,
		logger:      logger,
		outerDialer: outerDialer,
		mtu:         mtu,
		closeCtx:    closeCtx,
		closeFn:     closeFn,
	}, nil
}

// Start builds and launches the nebula tunnel plus the packet pumps between
// nebula and the gvisor netstack. The outer UDP socket is bound here (inside
// nebula.Main), once the network stack is up. It is non-blocking.
func (e *Endpoint) Start() error {
	e.started.once.Do(func() {
		e.started.err = e.start()
		if e.started.err == nil {
			e.started.done = true
		}
	})
	return e.started.err
}

func (e *Endpoint) start() error {
	// Fresh per-run cancellation: the outer UDP socket, both packet pumps and
	// the udpFactory dial all hang off closeCtx. On restart the old context is
	// cancelled before start(); a new one must replace it or the next tunnel
	// dies instantly. Base it on the original context, NOT the old closeCtx.
	closeCtx, closeFn := context.WithCancel(e.ctx)
	e.closeCtx = closeCtx
	e.closeFn = closeFn
	// UDP factory (nebula.UDPConnFactory seam): an unconnected socket so nebula
	// can receive from / send to arbitrary peer addresses (lighthouse discovery,
	// punchy, roaming). Nebula owns routines==1, so exactly one conn is produced.
	udpFactory := nebula.UDPConnFactory(func(l *slog.Logger, listenHost netip.Addr, port int, multi bool, batch int) (nebulaudp.Conn, error) {
		// Ignore nebula's listenHost/port: the dialer (DialerOptions) decides the
		// bind address. An unspecified destination yields a wildcard listen socket.
		pc, err := e.outerDialer.ListenPacket(e.closeCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, fmt.Errorf("nebula outbound UDP listen: %w", err)
		}
		// pc may be a sing-box wrapper (e.g. *route.trackedPacketConn), not a bare
		// *net.UDPConn — our adapter handles any net.PacketConn.
		return nebulaudp.NewPacketConnConn(l, pc), nil
	})

	// Inside (TUN) device: our queue-backed safeDevice. nebula.Main derives the
	// overlay networks from the node certificate and passes them as vpnNetworks;
	// we build safeDevice from the first one — the overlay address has a single
	// source of truth (the cert) rather than a redundant local_address field.
	var dev *safeDevice
	deviceFactory := overlay.DeviceFactory(func(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (overlay.Device, error) {
		if len(vpnNetworks) == 0 {
			return nil, fmt.Errorf("nebula Main passed no overlay networks")
		}
		dev = newSafeDevice(vpnNetworks[0])
		return dev, nil
	})

	ctrl, err := nebula.Main(e.cfg, false, "sing-box", e.logger, deviceFactory, udpFactory)
	if err != nil {
		return fmt.Errorf("nebula Main: %w", err)
	}
	// nebula.Main has invoked the factory by now, so dev is populated.
	if dev == nil {
		return fmt.Errorf("nebula Main did not create the tunnel device")
	}

	// Userspace netstack, mirroring nebula's service/service.go. Note: in this
	// gvisor version, udp.NewProtocol and icmp constructors take the *stack.Stack.
	ipstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			func(s *stack.Stack) stack.TransportProtocol { return udp.NewProtocol(s) },
			func(s *stack.Stack) stack.TransportProtocol { return icmp.NewProtocol4(s) },
			func(s *stack.Stack) stack.TransportProtocol { return icmp.NewProtocol6(s) },
		},
	})
	sack := tcpip.TCPSACKEnabled(true)
	if tcpErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); tcpErr != nil {
		return fmt.Errorf("enable TCP SACK: %v", tcpErr)
	}
	linkEP := channel.New(512, e.mtu, "")
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		return fmt.Errorf("create NIC: %v", err)
	}
	// Default route: everything egresses through the single NIC.
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFrom(strings.Repeat("\x00", 4)))
	ipstack.SetRouteTable([]tcpip.Route{{Destination: ipv4Subnet, NIC: nicID}})

	localIP := dev.cidr.Addr()
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(localIP.AsSlice()).WithPrefix(),
		Protocol:          ipv4.ProtocolNumber,
	}
	if localIP.Is6() {
		protoAddr.Protocol = ipv6.ProtocolNumber
	}
	if err := ipstack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add protocol address: %v", err)
	}

	e.ctrl = ctrl
	e.device = dev
	e.ipstack = ipstack
	e.linkEP = linkEP
	e.localIP = localIP

	ctrl.Start()

	// Pump A: tunnel → netstack. Packets nebula decrypted (device.Write) are
	// injected into gvisor as inbound.
	go func() {
		for {
			pkt, ok := e.device.nextInbound()
			if !ok {
				return
			}
			var netProto tcpip.NetworkProtocolNumber
			switch header.IPVersion(pkt) {
			case header.IPv4Version:
				netProto = header.IPv4ProtocolNumber
			case header.IPv6Version:
				netProto = header.IPv6ProtocolNumber
			default:
				continue
			}
			// Clone: pkt is reused/owned by the inbound queue's slice header space;
			// gvisor retains the PacketBuffer past InjectInbound.
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(pkt)),
			})
			e.linkEP.InjectInbound(netProto, pb)
			pb.DecRef()

			if err := e.closeCtx.Err(); err != nil {
				return
			}
		}
	}()

	// Pump B: netstack → tunnel. Packets the stack wants to send out the NIC are
	// written into nebula for encryption + UDP transmission.
	go func() {
		for {
			pkt := e.linkEP.ReadContext(e.closeCtx)
			if pkt == nil {
				if err := e.closeCtx.Err(); err != nil {
					return
				}
				continue
			}
			view := pkt.ToView()
			data := view.AsSlice()
			e.device.writeOutbound(data)
			view.Release()
		}
	}()

	return nil
}

// DialContext dials a TCP or UDP connection over the overlay netstack.
func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	fullAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(destination.Addr.AsSlice()),
		Port: destination.Port,
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return gonet.DialContextTCP(ctx, e.ipstack, fullAddr, protocolNumber(destination.Addr))
	case N.NetworkUDP:
		return gonet.DialUDP(e.ipstack, nil, &fullAddr, protocolNumber(destination.Addr))
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// ListenPacket binds an unconnected UDP socket over the overlay netstack.
func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(e.localIP.AsSlice())}
	return gonet.DialUDP(e.ipstack, &bind, nil, protocolNumber(e.localIP))
}

// Close stops the nebula tunnel first (so its listenIn loop sees the device
// close cleanly — avoiding nebula's os.Exit(2) on fatal read errors), then
// tears down the netstack. Safe to call if Start() was never called or failed.
func (e *Endpoint) Close() error {
	e.closed.once.Do(func() {
		e.closed.closed = true
		e.closeFn()
		e.restartAccess.Lock()
		defer e.restartAccess.Unlock()
		if e.started.done {
			e.ctrl.Stop()
			e.ipstack.Close()
		}
	})
	return nil
}

// Restart tears the tunnel down and brings it back up with a fresh outer UDP
// socket, so it binds through the new default interface. Called by the
// outbound's InterfaceUpdated: ResetNetwork closes the tracked outer UDP
// socket (ConnectionManager.CloseAll) and nebula never re-binds it on its own.
//
// Async (never blocks ResetNetwork's callback chain); restartAccess both
// serializes concurrent restarts and coalesces flaps into extra (harmless,
// idempotent) stop/start rounds.
func (e *Endpoint) Restart() {
	if e.closed.closed || !e.started.done {
		return
	}
	go func() {
		e.restartAccess.Lock()
		defer e.restartAccess.Unlock()
		if e.closed.closed || !e.started.done {
			return
		}
		// stop: see Close for the ordering rationale (ctrl.Stop drains
		// nebula's readers before the netstack goes away).
		e.closeFn()
		e.ctrl.Stop()
		e.ipstack.Close()
		if err := e.start(); err != nil {
			log.Error("nebula: restart failed: ", err)
			return
		}
		log.Info("nebula: tunnel restarted on interface change")
	}()
}

// nebulaLogBridge is a slog.Handler that forwards nebula's structured logs
// (v1.11.0 migrated from logrus to log/slog) into sing-box's log package, which
// mirrors to logcat on Android. Each record is dispatched by level; the message
// is prefixed with "nebula: " so it's identifiable in the merged stream.
type nebulaLogBridge struct {
	attrs  []slog.Attr
	groups []string
}

func (h *nebulaLogBridge) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelDebug
}

func (h *nebulaLogBridge) Handle(_ context.Context, r slog.Record) error {
	var msg strings.Builder
	msg.WriteString("nebula: ")
	msg.WriteString(r.Message)
	// Append attrs (record-level + handler-level) as key=value for context.
	appendAttrs := func(attrs []slog.Attr) {
		for _, a := range attrs {
			if a.Equal(slog.Attr{}) {
				continue
			}
			msg.WriteByte(' ')
			msg.WriteString(a.Key)
			msg.WriteByte('=')
			msg.WriteString(a.Value.String())
		}
	}
	appendAttrs(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		appendAttrs([]slog.Attr{a})
		return true
	})

	switch {
	case r.Level >= slog.LevelError:
		log.Error(msg.String())
	case r.Level >= slog.LevelWarn:
		log.Warn(msg.String())
	case r.Level >= slog.LevelInfo:
		log.Info(msg.String())
	default:
		log.Debug(msg.String())
	}
	return nil
}

func (h *nebulaLogBridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &nh
}

func (h *nebulaLogBridge) WithGroup(name string) slog.Handler {
	nh := *h
	nh.groups = append(append([]string(nil), h.groups...), name)
	return &nh
}

func protocolNumber(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

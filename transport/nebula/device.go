package nebula

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/routing"
)

// safeDevice is an overlay.Device that nebula reads from and writes to, backed by
// two queues instead of nebula's default io.Pipe implementation.
//
// Why not overlay.UserDevice: nebula's listenIn loop (interface.go) treats any
// read error other than os.ErrClosed as fatal and calls os.Exit(2). When
// UserDevice.Close() runs it closes the underlying io.Pipe, whose Read then
// returns io.EOF/io.ErrClosedPipe — neither satisfies errors.Is(os.ErrClosed) —
// so the process would be killed on shutdown. safeDevice returns os.ErrClosed
// from Read once closed, which the guard accepts.
//
// Direction (matches nebula's device contract):
//   - Read:  returns packets the host (our netstack pump) wants to send INTO the
//            tunnel, i.e. host→tunnel. nebula's listenIn consumes these.
//   - Write: accepts packets nebula decrypted FROM the tunnel, i.e. tunnel→host,
//            and queues them for our netstack pump to inject into gvisor.
type safeDevice struct {
	cidr netip.Prefix

	// routeTree holds the unsafe_routes lookup (nil when none are configured).
	// Built once before the device reaches nebula and read-only afterwards, so
	// no locking — the real tun uses an atomic pointer only because it supports
	// live config reload, which rebuilds this whole device instead.
	routeTree *bart.Table[routing.Gateways]
	// hasRoutes distinguishes "no unsafe_routes configured" from "configured but
	// no match", which RoutesFor treats differently.
	hasRoutes bool

	// outbound: host→tunnel packets, drained by Read() (nebula's listenIn),
	// filled by writeOutbound() (our gvisor egress pump).
	outbound struct {
		sync.Mutex
		cond   *sync.Cond
		queue  [][]byte
		closed bool
	}

	// inbound: tunnel→host packets, filled by Write() (nebula's listenOut path),
	// drained by nextInbound() (our gvisor ingress pump).
	inbound struct {
		sync.Mutex
		cond   *sync.Cond
		queue  [][]byte
		closed bool
	}

	closeOnce sync.Once
}

func newSafeDevice(cidr netip.Prefix, logger *slog.Logger, routes []overlay.Route) (*safeDevice, error) {
	d := &safeDevice{cidr: cidr, hasRoutes: len(routes) > 0}
	if len(routes) > 0 {
		// allowMTU=false: per-route MTU only applies to OS route installation,
		// which this userspace device never does (MakeRouteTree warns if set).
		tree, err := overlay.MakeRouteTree(logger, routes, false)
		if err != nil {
			return nil, fmt.Errorf("build unsafe route tree: %w", err)
		}
		d.routeTree = tree
	}
	d.outbound.cond = sync.NewCond(&d.outbound.Mutex)
	d.inbound.cond = sync.NewCond(&d.inbound.Mutex)
	return d, nil
}

// Read implements overlay.Device.Read: deliver one host→tunnel packet to nebula.
func (d *safeDevice) Read(p []byte) (int, error) {
	d.outbound.Lock()
	for len(d.outbound.queue) == 0 && !d.outbound.closed {
		d.outbound.cond.Wait()
	}
	if d.outbound.closed && len(d.outbound.queue) == 0 {
		d.outbound.Unlock()
		return 0, os.ErrClosed
	}
	pkt := d.outbound.queue[0]
	d.outbound.queue = d.outbound.queue[1:]
	d.outbound.Unlock()

	return copy(p, pkt), nil
}

// Write implements overlay.Device.Write: accept one tunnel→host packet from nebula.
func (d *safeDevice) Write(p []byte) (int, error) {
	clone := append([]byte(nil), p...) // p is nebula's buffer; reused after return
	d.inbound.Lock()
	defer d.inbound.Unlock()
	if d.inbound.closed {
		return 0, os.ErrClosed
	}
	d.inbound.queue = append(d.inbound.queue, clone)
	d.inbound.cond.Signal()
	return len(p), nil
}

// nextInbound returns the next tunnel→host packet, blocking until one is
// available or the device is closed.
func (d *safeDevice) nextInbound() ([]byte, bool) {
	d.inbound.Lock()
	for len(d.inbound.queue) == 0 && !d.inbound.closed {
		d.inbound.cond.Wait()
	}
	if d.inbound.closed && len(d.inbound.queue) == 0 {
		d.inbound.Unlock()
		return nil, false
	}
	pkt := d.inbound.queue[0]
	d.inbound.queue = d.inbound.queue[1:]
	d.inbound.Unlock()
	return pkt, true
}

// writeOutbound enqueues a host→tunnel packet (produced by gvisor) for nebula to read.
func (d *safeDevice) writeOutbound(p []byte) bool {
	clone := append([]byte(nil), p...)
	d.outbound.Lock()
	defer d.outbound.Unlock()
	if d.outbound.closed {
		return false
	}
	d.outbound.queue = append(d.outbound.queue, clone)
	d.outbound.cond.Signal()
	return true
}

func (d *safeDevice) Close() error {
	d.closeOnce.Do(func() {
		d.outbound.Lock()
		d.outbound.closed = true
		d.outbound.cond.Broadcast()
		d.outbound.Unlock()

		d.inbound.Lock()
		d.inbound.closed = true
		d.inbound.cond.Broadcast()
		d.inbound.Unlock()
	})
	return nil
}

// Remaining overlay.Device methods.
func (d *safeDevice) Activate() error                   { return nil }
func (d *safeDevice) Name() string                      { return "faketun0" }
func (d *safeDevice) Networks() []netip.Prefix          { return []netip.Prefix{d.cidr} }
func (d *safeDevice) SupportsMultiqueue() bool          { return false }

// RoutesFor resolves unsafe-route destinations to their via gateways. nebula
// only consults it for destinations OUTSIDE the overlay network (inside.go
// handles overlay destinations via the host map first). With unsafe_routes
// configured, a miss returns nil so nebula drops the packet immediately —
// native semantics, failing fast on a typo'd route. Without unsafe_routes the
// device keeps the legacy answer (gateway = the address itself, mirroring
// overlay.UserDevice's every-address-on-NIC behavior), which overlay
// destinations never see anyway.
func (d *safeDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	if d.routeTree != nil {
		if gateways, ok := d.routeTree.Lookup(ip); ok && len(gateways) > 0 {
			return gateways
		}
	}
	if d.hasRoutes {
		return nil
	}
	return routing.Gateways{routing.NewGateway(ip, 1)}
}

// NewMultiQueueReader returns the device itself. Only invoked when routines > 1,
// which we do not use (routines is fixed at 1), so this path is effectively
// unused — but the overlay.Device interface requires it.
func (d *safeDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

var _ overlay.Device = (*safeDevice)(nil)

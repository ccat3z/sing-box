package nebula

import (
	"io"
	"net/netip"
	"os"
	"sync"

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

func newSafeDevice(cidr netip.Prefix) *safeDevice {
	d := &safeDevice{cidr: cidr}
	d.outbound.cond = sync.NewCond(&d.outbound.Mutex)
	d.inbound.cond = sync.NewCond(&d.inbound.Mutex)
	return d
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

// RoutesFor mirrors overlay.UserDevice: every address is reachable directly
// over the single overlay NIC (gateway = the address itself, default route).
func (d *safeDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	return routing.Gateways{routing.NewGateway(ip, 1)}
}

// NewMultiQueueReader returns the device itself. Only invoked when routines > 1,
// which we do not use (routines is fixed at 1), so this path is effectively
// unused — but the overlay.Device interface requires it.
func (d *safeDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

var _ overlay.Device = (*safeDevice)(nil)

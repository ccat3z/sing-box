package nebula

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// fixedPortDialer binds the outer UDP socket to a fixed loopback port and
// records every conn it creates, mimicking sing-box's trackedPacketConn:
// closing the context (e.closeFn) closes the socket, exactly like the
// production ConnectionManager.CloseAll -> tracked conn close sequence that
// precedes every Restart() on iOS memory-pressure resets.
type fixedPortDialer struct {
	port int

	access    sync.Mutex
	conns     []net.PacketConn
	created   int
	failNext  int // number of next ListenPacket calls that fail (simulates bind failure during interface flux)
}

func (d *fixedPortDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *fixedPortDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	failed := false
	if d.failNext > 0 {
		d.failNext--
		failed = true
	}
	d.access.Unlock()
	if failed {
		return nil, fmt.Errorf("simulated bind failure (interface in flux)")
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", d.port))
	if err != nil {
		return nil, err
	}
	d.access.Lock()
	d.conns = append(d.conns, pc)
	d.created++
	d.access.Unlock()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	return pc, nil
}

// closeAll simulates ConnectionManager.CloseAll: every tracked conn is closed.
func (d *fixedPortDialer) closeAll() {
	d.access.Lock()
	defer d.access.Unlock()
	for _, pc := range d.conns {
		pc.Close()
	}
	d.conns = nil
}

func (d *fixedPortDialer) createdCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.created
}

func testCAPEM(t *testing.T) (string, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().Round(time.Second).Add(-2 * time.Second)
	ca, err := (&cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_CURVE25519,
		Name:      "test-ca",
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
		PublicKey: pub,
		IsCA:      true,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	}).Sign(nil, cert.Curve_CURVE25519, priv)
	require.NoError(t, err)
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)
	return string(caPEM), priv
}

func testNodePEMs(t *testing.T, caPEM string, caKey []byte, name, ip string) (string, string) {
	t.Helper()
	ca, _, err := cert.UnmarshalCertificateFromPEM([]byte(caPEM))
	require.NoError(t, err)
	priv := make([]byte, curve25519.ScalarSize)
	_, err = rand.Read(priv)
	require.NoError(t, err)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	require.NoError(t, err)
	// Same rounded "now" as the CA so the leaf can never outlive it on a
	// rounding race (nebula rejects "certificate expires after signing certificate").
	now := time.Now().Round(time.Second).Add(-2 * time.Second)
	node, err := (&cert.TBSCertificate{
		Version:   cert.Version1,
		Curve:     cert.Curve_CURVE25519,
		Name:      name,
		NotBefore: now,
		NotAfter:  now.Add(23 * time.Hour),
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix(ip + "/24")},
	}).Sign(ca, cert.Curve_CURVE25519, caKey)
	require.NoError(t, err)
	nodePEM, err := node.MarshalPEM()
	require.NoError(t, err)
	keyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
	return string(nodePEM), string(keyPEM)
}

func newTestEndpoint(t *testing.T, name, ip string, amLighthouse bool, port int, staticHostMap map[string][]string, hosts []string, caPEM string, caKey []byte) (*Endpoint, *fixedPortDialer) {
	t.Helper()
	nodePEM, keyPEM := testNodePEMs(t, caPEM, caKey, name, ip)
	e, err := New(context.Background(), option.NebulaOutboundOptions{
		PKI: option.NebulaPKI{
			CA:   caPEM,
			Cert: nodePEM,
			Key:  keyPEM,
		},
		StaticHostMap: staticHostMap,
		Lighthouse: option.NebulaLighthouse{
			Hosts:        hosts,
			AmLighthouse: amLighthouse,
		},
	})
	require.NoError(t, err)
	dialer := &fixedPortDialer{port: port}
	e.outerDialer = dialer
	if amLighthouse {
		// nebula requires listen.port for lighthouse nodes; the actual bind is
		// done by fixedPortDialer at this port (the udp factory ignores it).
		e.cfg.Settings["listen"] = map[string]any{"host": "127.0.0.1", "port": port}
	}
	require.NoError(t, e.Start())
	return e, dialer
}

func startOverlayEchoServer(t *testing.T, e *Endpoint, port uint16) {
	t.Helper()
	ln, err := gonet.ListenTCP(e.ipstack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4(e.localIP.As4()),
		Port: port,
	}, ipv4.ProtocolNumber)
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
}

// overlayEchoProbe dials the peer's echo server through the endpoint's overlay
// and verifies a round trip, returning an error instead of failing the test.
func overlayEchoProbe(e *Endpoint, target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := e.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(target))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	msg := []byte("ping-through-nebula-overlay")
	if _, err = conn.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, len(msg))
	if _, err = io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if !bytes.Equal(msg, buf) {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

// waitForEcho retries overlayEchoProbe until it succeeds or the deadline hits.
func waitForEcho(t *testing.T, e *Endpoint, target string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = overlayEchoProbe(e, target)
		if lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return lastErr
}

// TestEndpointRestartSurvivesTransientStartFailure tests the suspected iOS
// killer: during a reset the interface is in flux and the fresh outer UDP
// bind inside start() can fail once. Restart currently gives up on the first
// error, leaving the tunnel dead forever (matches "nebula stays unreachable
// until manual restart"). Traffic must recover on its own.
func TestEndpointRestartSurvivesTransientStartFailure(t *testing.T) {
	const (
		portA    = 33431
		portB    = 33432
		ipA      = "10.99.1.1"
		ipB      = "10.99.1.2"
		echoAddr = ipB + ":9999"
	)

	caPEM, caKey := testCAPEM(t)
	eB, _ := newTestEndpoint(t, "lighthouse-b", ipB, true, portB, nil, nil, caPEM, caKey)
	t.Cleanup(func() { eB.Close() })
	startOverlayEchoServer(t, eB, 9999)

	eA, dialerA := newTestEndpoint(t, "client-a", ipA, false, portA,
		map[string][]string{ipB: {fmt.Sprintf("127.0.0.1:%d", portB)}},
		[]string{ipB}, caPEM, caKey)
	t.Cleanup(func() { eA.Close() })

	require.NoError(t, overlayEchoProbe(eA, echoAddr))

	// Reset hits while the interface is flapping: the next UDP bind fails once.
	dialerA.access.Lock()
	dialerA.failNext = 1
	dialerA.access.Unlock()
	dialerA.closeAll()
	eA.Restart()

	err := waitForEcho(t, eA, echoAddr, 30*time.Second)
	if err != nil {
		t.Errorf("BUG REPRODUCED: tunnel never recovered from a single transient start failure: %v", err)
		return
	}
	t.Logf("traffic recovered after transient start failure")
}

// TestEndpointRestartUnderConcurrentTraffic restarts while connections are
// being dialed and streamed, the way an iOS reset fires mid-load.
func TestEndpointRestartUnderConcurrentTraffic(t *testing.T) {
	const (
		portA    = 33441
		portB    = 33442
		ipA      = "10.99.2.1"
		ipB      = "10.99.2.2"
		echoAddr = ipB + ":9999"
	)

	caPEM, caKey := testCAPEM(t)
	eB, _ := newTestEndpoint(t, "lighthouse-b", ipB, true, portB, nil, nil, caPEM, caKey)
	t.Cleanup(func() { eB.Close() })
	startOverlayEchoServer(t, eB, 9999)

	eA, dialerA := newTestEndpoint(t, "client-a", ipA, false, portA,
		map[string][]string{ipB: {fmt.Sprintf("127.0.0.1:%d", portB)}},
		[]string{ipB}, caPEM, caKey)
	t.Cleanup(func() { eA.Close() })

	require.NoError(t, overlayEchoProbe(eA, echoAddr))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Dialer loop: continuously open new overlay connections.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = overlayEchoProbe(eA, echoAddr)
			time.Sleep(200 * time.Millisecond)
		}
	}()

	for i := 1; i <= 5; i++ {
		dialerA.closeAll()
		eA.Restart()
		time.Sleep(300 * time.Millisecond)
	}

	// After the churn stops, traffic must work again.
	close(stop)
	wg.Wait()
	require.NoError(t, waitForEcho(t, eA, echoAddr, 30*time.Second), "traffic dead after concurrent restarts")
}

// TestEndpointRestartKeepsTrafficFlowing reproduces the iOS memory-pressure
// sequence: ConnectionManager.CloseAll closes the tracked outer UDP socket,
// then InterfaceUpdated calls Restart(). Traffic must keep (or recover)
// flowing after every round, indefinitely.
func TestEndpointRestartKeepsTrafficFlowing(t *testing.T) {
	const (
		portA    = 33421
		portB    = 33422
		ipA      = "10.99.0.1"
		ipB      = "10.99.0.2"
		echoAddr = ipB + ":9999"
		rounds   = 5
	)

	caPEM, caKey := testCAPEM(t)

	eB, _ := newTestEndpoint(t, "lighthouse-b", ipB, true, portB,
		nil, nil, caPEM, caKey)
	t.Cleanup(func() { eB.Close() })
	startOverlayEchoServer(t, eB, 9999)

	eA, dialerA := newTestEndpoint(t, "client-a", ipA, false, portA,
		map[string][]string{ipB: {fmt.Sprintf("127.0.0.1:%d", portB)}},
		[]string{ipB}, caPEM, caKey)
	t.Cleanup(func() { eA.Close() })

	// Round 0: baseline before any restart.
	require.NoError(t, overlayEchoProbe(eA, echoAddr), "baseline traffic failed")

	for i := 1; i <= rounds; i++ {
		// The production sequence: CloseAll kills the tracked outer socket…
		dialerA.closeAll()
		// …then the oomkiller/interface monitor calls Restart().
		eA.Restart()

		err := waitForEcho(t, eA, echoAddr, 30*time.Second)
		require.NoError(t, err, "round %d: traffic did not recover after Restart", i)
		t.Logf("round %d: traffic recovered (outer conns created so far: %d)", i, dialerA.createdCount())
	}
}

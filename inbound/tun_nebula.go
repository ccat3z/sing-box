package inbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sirupsen/logrus"

	"github.com/slackhq/nebula"
	ncidr "github.com/slackhq/nebula/cidr"
	nconfig "github.com/slackhq/nebula/config"
	niputil "github.com/slackhq/nebula/iputil"
	noverlay "github.com/slackhq/nebula/overlay"
)

type nebulaDevice struct {
	cidr      *net.IPNet
	routeTree *ncidr.Tree4[niputil.VpnIp]
	*io.PipeReader
	*io.PipeWriter
}

type NebulaTun struct {
	logger log.ContextLogger
	ctl    *nebula.Control
	prefix netip.Prefix
	*io.PipeReader
	*io.PipeWriter
}

type infoLoggerWriter struct {
	logger log.ContextLogger
}

func (w infoLoggerWriter) Write(data []byte) (n int, err error) {
	w.logger.Info("nebula ", string(data[:]))
	return len(data), nil
}

func NewNebulaTun(ctx context.Context, logger log.ContextLogger, config string) (tun.RouteTun, error) {
	nebulaLogger := logrus.New()
	nebulaLogger.SetOutput(infoLoggerWriter{logger})

	nebulaConfig := nconfig.NewC(nebulaLogger)
	err := nebulaConfig.LoadString(config)
	if err != nil {
		return nil, E.Cause(err, "Failed to load nebula config")
	}

	tun := &NebulaTun{
		logger: logger,
	}
	ctl, err := nebula.Main(nebulaConfig, false, "sing-box", nebulaLogger, func(c *nconfig.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (noverlay.Device, error) {
		prefix, err := netip.ParsePrefix(tunCidr.String())
		if err != nil {
			return nil, E.Cause(err, "parse cidr")
		}
		tun.prefix = prefix

		dev := &nebulaDevice{
			cidr:      tunCidr,
			routeTree: ncidr.NewTree4[niputil.VpnIp](),
		}
		tun.PipeReader, dev.PipeWriter = io.Pipe()
		dev.PipeReader, tun.PipeWriter = io.Pipe()

		return dev, nil
	})
	if err != nil {
		return nil, E.Cause(err, "Failed to setup nebula")
	}
	tun.ctl = ctl

	ctl.Start()
	return tun, nil
}

func (nt *NebulaTun) Close() error {
	nt.ctl.Stop()

	err := nt.PipeReader.Close()
	if err != nil {
		return err
	}

	err = nt.PipeWriter.Close()
	if err != nil {
		return err
	}

	return nil
}

func (nt *NebulaTun) Prefix() netip.Prefix {
	return nt.prefix
}

func (t *nebulaDevice) RouteFor(ip niputil.VpnIp) niputil.VpnIp {
	_, r := t.routeTree.MostSpecificContains(ip)
	return r
}

func (t nebulaDevice) Activate() error {
	return nil
}

func (t *nebulaDevice) Cidr() *net.IPNet {
	return t.cidr
}

func (t *nebulaDevice) Name() string {
	return "sing-box"
}

func (t *nebulaDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}

func (t *nebulaDevice) Close() error {
	err := t.PipeReader.Close()
	if err != nil {
		return err
	}

	err = t.PipeWriter.Close()
	if err != nil {
		return err
	}

	return nil
}

func (t *nebulaDevice) Read(p []byte) (int, error) {
	n, err := t.PipeReader.Read(p)
	if err == io.ErrClosedPipe {
		// nebula only accept os.ErrClosed
		// otherwise, nebula will kill the process (os.Exit)
		err = os.ErrClosed
	}
	return n, err
}

var (
	_ noverlay.Device = (*nebulaDevice)(nil)
	_ tun.RouteTun    = (*NebulaTun)(nil)
)

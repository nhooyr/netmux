package netmux_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/nhooyr/netmux"
	"github.com/nhooyr/netmux/detector"
	"github.com/nhooyr/netmux/handler"
	"github.com/nhooyr/netmux/tlsmux"
)

const certRoot = "/usr/local/etc/dotfiles/certs/aubble.com/"

func TestServe(t *testing.T) {
	cert, err := tls.LoadX509KeyPair(certRoot+"cert.pem", certRoot+"key.pem")
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"super"}}
	responderXD := &tlsmux.NetmuxWrapper{handler.NewResponseHandler([]byte("xd"))}
	responderSuper := &tlsmux.NetmuxWrapper{handler.NewResponseHandler([]byte("Super"))}
	superService := tlsmux.NewService(tlsmux.ProtoDetector([]string{"super"}), responderSuper)
	tlsServer := tlsmux.NewServer([]tlsmux.Service{superService}, responderXD)
	tlsHandshaker := tlsmux.NewHandshaker(config, tlsServer)

	tlsService := netmux.NewService(detector.TLSDetector, tlsHandshaker)
	srvcs := []netmux.Service{tlsService}
	s := netmux.NewServer(srvcs, nil)

	l, err := net.Listen("tcp", ":3333")
	if err != nil {
		t.Fatal(err)
	}
	s.Serve(l)
}

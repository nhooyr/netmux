package tlsmux

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net"
	"sync"

	"github.com/nhooyr/netmux/handler"
	"github.com/rjeczalik/notify"
)

type Detector interface {
	Detect(state *tls.ConnectionState) (ok bool)
}

type Handler interface {
	Handle(c *tls.Conn)
}

type Service interface {
	Detector
	Handler
}

type service struct {
	Detector
	Handler
}

func NewService(d Detector, h Handler) Service {
	return &service{d, h}
}

type ProtoDetector []string

func (protos ProtoDetector) Detect(state *tls.ConnectionState) bool {
	for _, s := range protos {
		if s == state.NegotiatedProtocol {
			return true
		}
	}
	return false
}

type ServerDetector []string

func (names ServerDetector) Detect(state *tls.ConnectionState) bool {
	for _, name := range names {
		if name == state.ServerName {
			return true
		}
	}
	return false
}

// TODO how to handle when CRL and peer's certificate issuer are different
type RevokedDetector struct {
	revokedCerts []pkix.RevokedCertificate
	mu           sync.RWMutex
}

func parseCRL(path string) ([]pkix.RevokedCertificate, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseCRL(f)
	if err != nil {
		return nil, err
	}
	return crl.TBSCertList.RevokedCertificates, nil
}

func NewRevokedDetector(crlPath string) (rd *RevokedDetector, err error) {
	rd = new(RevokedDetector)
	rd.revokedCerts, err = parseCRL(crlPath)
	if err != nil {
		return nil, err
	}
	c := make(chan notify.EventInfo, 1)
	err = notify.Watch(crlPath, c, notify.Write)
	if err != nil {
		return nil, err
	}
	go func() {
		defer notify.Stop(c)
		for {
			<-c
			rd.mu.Lock()
			rd.revokedCerts, err = parseCRL(crlPath)
			if err != nil {
				panic(err)
			}
			rd.mu.Unlock()
		}
	}()
	return rd, nil
}

func (rd RevokedDetector) Detect(state *tls.ConnectionState) bool {
	rd.mu.RLock()
	defer rd.mu.RUnlock()
	for _, rc := range rd.revokedCerts {
		if state.PeerCertificates[0].SerialNumber.Cmp(rc.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func (_ RevokedDetector) Handle(c *tls.Conn) {
	c.Close()
}

type Server struct {
	srvcs    []Service
	fallback Handler
}

func (s Server) Handle(c *tls.Conn) {
	state := c.ConnectionState()
	for _, srvc := range s.srvcs {
		if srvc.Detect(&state) {
			srvc.Handle(c)
			return
		}
	}
	if s.fallback != nil {
		s.fallback.Handle(c)
	}
	c.Close()
}

func NewServer(srvcs []Service, fallback Handler) *Server {
	return &Server{srvcs, fallback}
}

type Handshaker struct {
	config *tls.Config
	next   Handler
}

func (hs *Handshaker) Handle(c net.Conn) {
	tc := tls.Server(c, hs.config)
	if tc.Handshake() != nil {
		c.Close()
		return
	}
	hs.next.Handle(tc)
}

func NewHandshaker(config *tls.Config, next Handler) *Handshaker {
	return &Handshaker{config, next}
}

type NetmuxWrapper struct {
	handler.Handler
}

func (h *NetmuxWrapper) Handle(c *tls.Conn) {
	h.Handler.Handle(c)
}

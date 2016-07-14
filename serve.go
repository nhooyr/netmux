package netmux

import (
	"net"

	"github.com/nhooyr/netmux/detect"
	"github.com/nhooyr/netmux/handle"
)

type Service interface {
	detect.Detector
	handle.Handler
}

type service struct {
	detect.Detector
	handle.Handler
}

func NewService(p detect.Detector, h handle.Handler) Service {
	return &service{p, h}
}

type Server struct {
	services       []Service
	fallback       Service
	maxHeaderBytes int
}

func NewServer(fallback Service, srvcs ...Service) *Server {
	s := &Server{
		services: srvcs,
		fallback: nil,
	}
	s.maxHeaderBytes = srvcs[0].MaxHeaderBytes()
	if fallback != nil {
		srvcs = append(srvcs, fallback)
	}
	for i := 1; i < len(srvcs); i++ {
		n := srvcs[i].MaxHeaderBytes()
		if s.maxHeaderBytes < n {
			s.maxHeaderBytes = n
		}
	}
	return s
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	header := make([]byte, 0, s.maxHeaderBytes+128)
	srvcs := append([]Service(nil), s.services...)
	for len(srvcs) > 0 && len(header) < s.maxHeaderBytes {
		n, err := c.Read(header[len(header):cap(header)])
		if err != nil {
			break
		}
		header = header[:len(header)+n]

		for i := 0; i < len(srvcs); i++ {
			srvc := srvcs[i]
			status := srvc.Detect(header)
			switch {
			case status == detect.Success:
				s.handle(srvc, header, c)
				return
			case status == detect.Rejected && len(header) < s.maxHeaderBytes:
				srvcs = append(srvcs[:i], srvcs[i+1:]...)
				i--
			}
		}
	}

	if s.fallback != nil {
		s.handle(s.fallback, nil, c)
		return
	}

	c.Close()
}

func (s *Server) handle(h handle.Handler, header []byte, c net.Conn) {
	hc := newHeaderConn(header, c)
	c = h.Handle(hc)
	if c != nil {
		s.serve(c)
	}
}

type headerConn struct {
	header []byte
	net.Conn
}

func newHeaderConn(header []byte, c net.Conn) *headerConn {
	return &headerConn{header, c}
}
func (hc *headerConn) Read(p []byte) (n int, err error) {
	if hc.header != nil {
		copy(p, hc.header)
		if len(hc.header) > len(p) {
			hc.header = hc.header[len(p):]
			return len(p), nil
		}
		if len(hc.header) == len(p) {
			hc.header = nil
			return len(p), nil
		}
		n, err = hc.Conn.Read(p[len(hc.header):])
		n += len(hc.header)
		hc.header = nil
		return n, err
	}
	return hc.Conn.Read(p)
}

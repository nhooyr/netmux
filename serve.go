package netmux

import (
	"net"

	"github.com/nhooyr/netmux/detector"
	"github.com/nhooyr/netmux/handler"
)

type Service interface {
	detector.Detector
	handler.Handler
}

type service struct {
	detector.Detector
	handler.Handler
}

func NewService(d detector.Detector, h handler.Handler) Service {
	return &service{d, h}
}

type Server struct {
	services       []Service
	fallback       handler.Handler
	maxHeaderBytes int
}

func NewServer(srvcs []Service, fallback handler.Handler) *Server {
	s := &Server{
		services: srvcs,
		fallback: nil,
	}
	s.maxHeaderBytes = srvcs[0].MaxHeaderBytes()
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

		go s.Handle(c)
	}
}

func (s *Server) ServeTLS(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go s.Handle(c)
	}
}

func (s *Server) Handle(c net.Conn) {
	header := make([]byte, 0, s.maxHeaderBytes)
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
			case status == detector.StatusAccepted:
				srvc.Handle(newHeaderConn(header, c))
				return
			case status == detector.StatusRejected && len(header) < s.maxHeaderBytes:
				srvcs = append(srvcs[:i], srvcs[i+1:]...)
				i--
			}
		}
	}

	if s.fallback != nil {
		s.fallback.Handle(newHeaderConn(header, c))
		return
	}

	c.Close()
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

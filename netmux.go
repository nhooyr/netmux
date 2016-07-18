package netmux

import (
	"net"
)

type Detector interface {
	Detect(header []byte) DetectStatus
}

// TODO rename perhaps?
type DetectStatus int

const (
	DetectAccepted DetectStatus = iota
	DetectUncertain
	DetectRejected
)

type Handler interface {
	Handle(c net.Conn)
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

type Server struct {
	services []Service
	fallback Handler
}

func NewServer(srvcs []Service, fallback Handler) *Server {
	s := &Server{
		services: srvcs,
		fallback: nil,
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

// TODO better way to do this
const MaxHeaderBytes = 128

func (s *Server) Handle(c net.Conn) {
	header := make([]byte, 0, MaxHeaderBytes)
	srvcs := append([]Service(nil), s.services...)
	for len(srvcs) > 0 && len(header) < MaxHeaderBytes {
		n, err := c.Read(header[len(header):MaxHeaderBytes])
		if err != nil {
			break
		}
		header = header[:len(header)+n]

		for i := 0; i < len(srvcs); i++ {
			srvc := srvcs[i]
			status := srvc.Detect(header)
			switch {
			case status == DetectAccepted:
				srvc.Handle(newHeaderConn(header, c))
				return
			case status == DetectRejected && len(header) < MaxHeaderBytes:
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

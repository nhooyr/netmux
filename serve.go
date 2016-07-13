package netmux

import (
	"net"
	"sync"
)

type Detector interface {
	Detect(header []byte) DetectorStatus
}

type DetectorStatus int

const (
	DetectRejected DetectorStatus = iota
	DetectMore
	DetectSuccess
)

type Handler interface {
	Handle(c net.Conn) net.Conn
}

type Service interface {
	Detector
	Handler
}

type service struct {
	Detector
	Handler
}

func NewService(p Detector, h Handler) Service {
	return &service{p, h}
}

type Server struct {
	headerPool *sync.Pool
	services   []Service
	fallback   Service
}

func NewServer(srvcs ...Service) *Server {
	s := &Server{
		services: srvcs,
		fallback: nil,
	}
	return s
}

type option func(*Server)

func (s *Server) Option(opts ...option) {
	for _, opt := range opts {
		opt(s)
	}
}

func Fallback(srvc Service) option {
	return func(s *Server) {
		s.fallback = srvc
	}
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

const maxHeaderBytes = 64

var headerPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, maxHeaderBytes)
	},
}

func (s *Server) serve(c net.Conn) {
	header := headerPool.Get().([]byte)
	srvcs := append([]Service(nil), s.services...)
	for len(srvcs) > 0 && len(header) != maxHeaderBytes {
		n, err := c.Read(header[len(header):maxHeaderBytes])
		if err != nil {
			break
		}
		header = header[:len(header)+n]

		for i := 0; i < len(srvcs); i++ {
			srvc := srvcs[i]
			switch srvc.Detect(header) {
			case DetectSuccess:
				s.handle(srvc, header, c)
				return
			case DetectRejected:
				srvcs = append(srvcs[:i], srvcs[i+1:]...)
				i--
			}
		}
	}

	if s.fallback != nil {
		s.handle(s.fallback, nil, c)
		return
	}

	headerPool.Put(header[:0])
	c.Close()
}

func (s *Server) handle(h Handler, header []byte, c net.Conn) {
	hc := newHeaderConn(header, c)
	c = h.Handle(hc)
	if hc.header != nil {
		headerPool.Put(hc.header[:0])
	}
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
			headerPool.Put(hc.header[:0])
			hc.header = nil
			return len(p), nil
		}
		n, err = hc.Conn.Read(p[len(hc.header):])
		n += len(hc.header)
		headerPool.Put(hc.header[:0])
		hc.header = nil
		return n, err
	}
	return hc.Conn.Read(p)
}

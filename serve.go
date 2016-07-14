package netmux

import "net"

type Detector interface {
	Detect(header []byte) DetectorStatus
	Max() int
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
	services       []Service
	fallback       Service
	maxHeaderBytes int
}

func NewServer(fallback Service, srvcs ...Service) *Server {
	if len(srvcs) == 0 {
		panic("length of services is 0")
	}
	s := &Server{
		services: srvcs,
		fallback: nil,
	}
	if fallback != nil {
		srvcs = append(srvcs, fallback)
	}
	s.maxHeaderBytes = srvcs[0].Max()
	for i := 1; i < len(srvcs); i++ {
		n := srvcs[i].Max()
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
	header := make([]byte, 0, s.maxHeaderBytes)
	srvcs := append([]Service(nil), s.services...)
	for len(srvcs) > 0 && len(header) != cap(header) {
		n, err := c.Read(header[len(header):cap(header)])
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

	c.Close()
}

func (s *Server) handle(h Handler, header []byte, c net.Conn) {
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

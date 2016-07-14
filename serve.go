package netmux

import (
	"net"
	"sync"
	"time"

	"github.com/nhooyr/color/log"
)

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
	headerPool *sync.Pool
	services   []Service
	fallback   Service
}

func NewServer(fallback Service, srvcs ...Service) *Server {
	s := &Server{
		services: srvcs,
		fallback: nil,
	}
	var max, n int
	for _, srvc := range srvcs {
		n = srvc.Max()
		if max < n {
			max = n
		}
	}
	if fallback != nil {
		n = fallback.Max()
		if max < n {
			max = n
		}
	}

	var ok bool
	s.headerPool, ok = headerPools[max]
	if !ok {
		s.headerPool = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, max)
			},
		}
		headerPools[max] = s.headerPool
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

var headerPools = make(map[int]*sync.Pool)

var count, sum time.Duration

func (s *Server) serve(c net.Conn) {
	now := time.Now()
	header := s.headerPool.Get().([]byte)
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
				count++
				sum += time.Since(now)
				log.Print(sum / count)
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

	s.headerPool.Put(header[:0])
	c.Close()
}

func (s *Server) handle(h Handler, header []byte, c net.Conn) {
	hc := newHeaderConn(header, s.headerPool, c)
	c = h.Handle(hc)
	if hc.header != nil {
		s.headerPool.Put(hc.header[:0])
	}
	if c != nil {
		s.serve(c)
	}
}

type headerConn struct {
	header     []byte
	headerPool *sync.Pool
	net.Conn
}

func newHeaderConn(header []byte, headerPool *sync.Pool, c net.Conn) *headerConn {
	return &headerConn{header, headerPool, c}
}
func (hc *headerConn) Read(p []byte) (n int, err error) {
	if hc.header != nil {
		copy(p, hc.header)
		if len(hc.header) > len(p) {
			hc.header = hc.header[len(p):]
			return len(p), nil
		}
		if len(hc.header) == len(p) {
			hc.headerPool.Put(hc.header[:0])
			hc.header = nil
			return len(p), nil
		}
		n, err = hc.Conn.Read(p[len(hc.header):])
		n += len(hc.header)
		hc.headerPool.Put(hc.header[:0])
		hc.header = nil
		return n, err
	}
	return hc.Conn.Read(p)
}

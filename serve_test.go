package netmux

import (
	"net"
	"testing"

	"github.com/nhooyr/netmux/detector"
	"github.com/nhooyr/netmux/handler"
)

var (
	req  = []byte("ECHO")
	resp = make([]byte, 99999)
)

func BenchmarkServe(b *testing.B) {
	d := detector.NewMagicsDetector([][]byte{req})
	h := handler.NewResponseHandler(resp)
	s := NewServer(nil, NewService(d, h))
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}
	go writeEcho(l.Addr())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := l.Accept()
		if err != nil {
			b.Fatal(err)
		}
		s.Handle(c)
	}
	l.Close()
}

func writeEcho(addr net.Addr) {
	for {
		c, err := net.Dial(addr.Network(), addr.String())
		if err != nil {
			continue
		}
		c.Write(req)
		c.Write(resp)
		c.Read(resp)
		c.Close()
	}
}

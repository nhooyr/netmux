package main

import (
	"bytes"
	"net"

	"github.com/nhooyr/color/log"
	"github.com/nhooyr/netmux"
)

type simpleMatcher struct {
	magic []byte
}

func (m *simpleMatcher) Detect(header []byte) netmux.ProtocolStatus {
	if len(m.magic) > len(header) {
		if bytes.Equal(m.magic[:len(header)], header) {
			return netmux.StatusMore
		}
	} else if bytes.Equal(m.magic, header[:len(m.magic)]) {
		return netmux.StatusDetected
	}
	return netmux.StatusRejected
}

type simpleHandler struct {
	response []byte
}

func (h *simpleHandler) Handle(c net.Conn) net.Conn {
	defer c.Close()
	c.Write(h.response)
	return nil
}

func main() {
	xd := netmux.NewService(&simpleMatcher{[]byte("xd")}, &simpleHandler{[]byte("ixday")})
	one := netmux.NewService(&simpleMatcher{[]byte("one")}, &simpleHandler{[]byte("two")})
	l, err := net.Listen("tcp", ":3333")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(netmux.NewServer(xd, one).Serve(l))
}

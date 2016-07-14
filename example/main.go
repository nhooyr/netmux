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

func (m *simpleMatcher) Detect(header []byte) netmux.DetectorStatus {
	if len(m.magic) > len(header) {
		if bytes.HasPrefix(m.magic, header) {
			return netmux.DetectMore
		}
	} else if bytes.HasPrefix(header, m.magic) {
		return netmux.DetectSuccess
	}
	return netmux.DetectRejected
}

func (m *simpleMatcher) Max() int {
	return len(m.magic)
}

type simpleHandler struct {}

var resp = []byte("SSH")

func (h *simpleHandler) Handle(c net.Conn) net.Conn {
	defer c.Close()
	for i := 0; i < 100; i++ {
		c.Write(resp)
	}
	return nil
}

func main() {
	ssh := netmux.NewService(&simpleMatcher{[]byte("SSH")}, &simpleHandler{})
	l, err := net.Listen("tcp", "localhost:3333")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(netmux.NewServer(nil, ssh).Serve(l))
}

package handle

import "net"

type Handler interface {
	Handle(c net.Conn) net.Conn
}

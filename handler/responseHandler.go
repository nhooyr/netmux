package handler

import "net"

type responseHandler struct {
	resp []byte
}

func (rh *responseHandler) Handle(c net.Conn) {
	c.Write(rh.resp)
}

func NewResponseHandler(resp []byte) *responseHandler {
	return &responseHandler{resp}
}

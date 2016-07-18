package handler

import "net"

type ResponseHandler struct {
	resp []byte
}

func (rh *ResponseHandler) Handle(c net.Conn) {
	c.Write(rh.resp)
	c.Close()
}

func NewResponseHandler(resp []byte) *ResponseHandler {
	return &ResponseHandler{resp}
}

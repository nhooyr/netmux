package tlsmux

import (
	"crypto/tls"
	"net"

	"github.com/nhooyr/netmux/handler"
)

type Service interface {
	Match(state *tls.ConnectionState) (ok bool)
	handler.Handler
}

type ProtoMatcher []string

func (protos ProtoMatcher) Match(state *tls.ConnectionState) bool {
	for _, s := range protos {
		if s == state.NegotiatedProtocol {
			return true
		}
	}
	return false
}

type ServerMatcher []string

func (names ServerMatcher) Match(state *tls.ConnectionState) bool {
	for _, s := range names {
		if s == state.ServerName {
			return true
		}
	}
	return false
}

type Handler struct {
	config *tls.Config
	checks []Service
}

func NewHandler(config *tls.Config, srvcs []Service) *Handler {
	return &Handler{config, srvcs}
}

func (th *Handler) Handle(c net.Conn) {
	tc := tls.Server(c, th.config)
	if tc.Handshake() != nil {
		return
	}
	// TODO is indirect optimized?
	state := tc.ConnectionState()
	for _, tm := range th.checks {
		if tm.Match(&state) {
			tm.Handle(tc)
			return
		}
	}
}

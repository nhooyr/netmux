package detect

import "crypto/tls"

const (
	TLSMajor        = tls.VersionTLS12 & 0x00FF
	TLSHighestMinor = tls.VersionTLS12 & 0xFF // Bump when new releases are made available
	TLSHandshake    = 0x16
	TLSClientHello  = 0x01
)

type TLS tls.Config

func (t *TLS) Detect(header []byte) Status {
	switch {
	case len(header) >= 6:
		if header[5] == TLSClientHello {
			fallthrough
		}
	case len(header) >= 3:
		if header[2] <= TLSHighestMinor {
			fallthrough
		}
	case len(header) == 2:
		if header[1] == TLSMajor {
			fallthrough
		}
	case len(header) == 1:
		if header[0] == TLSHandshake {
			if len(header) < 6 {
				return More
			}
			return Success
		}
	}
	return Rejected
}

func (t *TLS) MaxHeaderBytes() int {
	return 6
}

package detector

import (
	"crypto/tls"
)

const (
	TLSHandshake    = 0x16
	TLSMajor        = tls.VersionTLS12 >> 8
	TLSHighestMinor = tls.VersionTLS12 & 0xFF
	TLSClientHello  = 0x01
)

type TLS struct{}

func (_ TLS) Detect(header []byte) Status {
	if len(header) < 6 {
		switch {
		case len(header) >= 3:
			if header[2] > TLSHighestMinor {
				break
			}
			fallthrough
		case len(header) == 2:
			if header[1] != TLSMajor {
				break
			}
			fallthrough
		case len(header) == 1:
			if header[0] != TLSHandshake {
				break
			}
			return StatusUncertain
		}
	} else if header[0] == TLSHandshake &&
		header[1] == TLSMajor &&
		header[2] <= TLSHighestMinor &&
		header[5] == TLSClientHello {
		return StatusAccepted
	}
	return StatusRejected
}

func (_ TLS) MaxHeaderBytes() int {
	return 6
}

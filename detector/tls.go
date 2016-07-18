package detector

import (
	"crypto/tls"
)

const (
	tlsHandshake    = 0x16
	tlsMajor        = tls.VersionTLS12 >> 8
	tlsHighestMinor = tls.VersionTLS12 & 0xFF
	tlsClientHello  = 0x01
)

type tlsDetector struct{}

func (_ tlsDetector) Detect(header []byte) (detected, certain bool) {
	if len(header) < 6 {
		switch {
		case len(header) >= 3:
			if header[2] > tlsHighestMinor {
				break
			}
			fallthrough
		case len(header) == 2:
			if header[1] != tlsMajor {
				break
			}
			fallthrough
		case len(header) == 1:
			if header[0] != tlsHandshake {
				break
			}
			return false, false
		}
	} else if header[0] == tlsHandshake &&
		header[1] == tlsMajor &&
		header[2] <= tlsHighestMinor &&
		header[5] == tlsClientHello {
		return StatusAccepted
	}
	return StatusRejected
}

func (_ tlsDetector) MaxHeaderBytes() int {
	return 6
}

var TLSDetector tlsDetector

package detector

import "crypto/tls"

const (
	TLSMajor        = tls.VersionTLS12 >> 8
	TLSHighestMinor = tls.VersionTLS12 & 0xFF // Bump when new releases are made available
	TLSHandshake    = 0x16
	TLSClientHello  = 0x01
)

type TLS tls.Config

func (t *TLS) Detect(header []byte) Status {
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
			return More
		}
	} else if header[0] == TLSHandshake &&
		header[1] == TLSMajor &&
		header[2] <= TLSHighestMinor &&
		header[5] == TLSClientHello {
		return Success
	}
	return Rejected
}

func (t *TLS) MaxHeaderBytes() int {
	return 6
}

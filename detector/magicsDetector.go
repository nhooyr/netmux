package detector

import (
	"bytes"

	"github.com/nhooyr/netmux"
)

type MagicsDetector struct {
	magics [][]byte
}

func (m *MagicsDetector) Detect(header []byte) netmux.DetectStatus {
	for _, magic := range m.magics {
		if len(magic) > len(header) {
			if bytes.HasPrefix(magic, header) {
				return netmux.DetectUncertain
			}
		} else if bytes.HasPrefix(header, magic) {
			return netmux.DetectAccepted
		}
	}
	return netmux.DetectRejected
}

func NewMagicsDetector(magics [][]byte) *MagicsDetector {
	return &MagicsDetector{magics}
}

var HTTP = NewMagicsDetector(
	[][]byte{
		[]byte("GET"),
		[]byte("PUT"),
		[]byte("HEAD"),
		[]byte("POST"),
		[]byte("PATCH"),
		[]byte("TRACE"),
		[]byte("DELETE"),
		[]byte("CONNECT"),
		[]byte("OPTIONS"),
	},
)

var SSH = NewMagicsDetector(
	[][]byte{
		[]byte("SSH"),
	},
)

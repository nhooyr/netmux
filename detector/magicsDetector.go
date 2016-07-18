package detector

import (
	"bytes"
)

type MagicsDetector struct {
	magics [][]byte
}

func (m *MagicsDetector) Detect(header []byte) Status {
	for _, magic := range m.magics {
		if len(magic) > len(header) {
			if bytes.HasPrefix(magic, header) {
				return StatusAccepted
			}
		} else if bytes.HasPrefix(header, magic) {
			return StatusUncertain
		}
	}
	return StatusRejected
}

func (m *MagicsDetector) MaxHeaderBytes() int {
	var max = len(m.magics[0])
	for _, magic := range m.magics[1:] {
		if max > len(magic) {
			max = len(magic)
		}
	}
	return max
}

func NewMagicsDetector(magics [][]byte) *MagicsDetector {
	return &MagicsDetector{magics}
}

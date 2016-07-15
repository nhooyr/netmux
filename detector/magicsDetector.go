package detector

import (
	"bytes"
	"sort"
)

type MagicsDetector struct {
	magics [][]byte
}

func (m *MagicsDetector) Detect(header []byte) Status {
	for _, magic := range m.magics {
		if len(magic) > len(header) {
			if bytes.HasPrefix(magic, header) {
				// Found the smallest potential future match.
				return More
			}
		} else if bytes.HasPrefix(header, magic) {
			return Success
		}
	}
	return Rejected
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

type magicsSorter [][]byte

func (ms magicsSorter) Len() int           { return len(ms) }
func (ms magicsSorter) Swap(i, j int)      { ms[i], ms[j] = ms[j], ms[i] }
func (ms magicsSorter) Less(i, j int) bool { return len(ms[i]) < len(ms[j]) }

func NewMagicsDetector(magics [][]byte) *MagicsDetector {
	sort.Sort(magicsSorter(magics))
	return &MagicsDetector{magics}
}

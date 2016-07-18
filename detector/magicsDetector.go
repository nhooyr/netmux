package detector

import (
	"bytes"
	"sort"
)

type MagicsDetector struct {
	magics [][]byte
}

func (m *MagicsDetector) Detect(header []byte) (detected bool, certain bool) {
	for _, magic := range m.magics {
		if len(magic) > len(header) {
			return bytes.HasPrefix(magic, header), false
		} else {
			return bytes.HasPrefix(header, magic), true
		}
	}
	return false, true
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

type magicSorter [][]byte

func (ms magicSorter) Len() int           { return len(ms) }
func (ms magicSorter) Swap(i, j int)      { ms[i], ms[j] = ms[j], ms[i] }
func (ms magicSorter) Less(i, j int) bool { return len(ms[i]) < len(ms[j]) }

func NewMagicsDetector(magics [][]byte) *MagicsDetector {
	sort.Sort(magicSorter(magics))
	return &MagicsDetector{magics}
}

package detector

type Detector interface {
	Detect(header []byte) Status
	MaxBytes() int
}

type Status int

const (
	StatusRejected Status = iota
	StatusUncertain
	StatusAccepted
)

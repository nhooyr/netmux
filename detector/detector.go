package detector

type Detector interface {
	Detect(header []byte) Status
	MaxHeaderBytes() int
}

type Status int

const (
	StatusRejected Status = iota
	StatusUncertain
	StatusAccepted
)

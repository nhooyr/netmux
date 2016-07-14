package detect

type Detector interface {
	Detect(header []byte) Status
	MaxHeaderBytes() int
}

type Status int

const (
	Rejected Status = iota
	More
	Success
)

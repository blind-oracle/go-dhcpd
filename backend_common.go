package main

type Backend interface {
	Init() error
	LeaseCheckAndDelete(*ReqCtx) error
	LeaseCheckAndUpdate(*ReqCtx) error
	LeaseFind(*ReqCtx) error
}

// Constructor
func ConstructBackend() Backend {
	return &BackendHash{}
}

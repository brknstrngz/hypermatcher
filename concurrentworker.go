package hyperscanner

import (
	"errors"

	"github.com/flier/gohs/hyperscan"
)

// ConcurrentWorker is a scanning worker
type ConcurrentWorker struct {
	stopChan    chan struct{}
	requestChan chan concurrentScanRequest
	refreshChan chan hyperscan.VectoredDatabase
	db          hyperscan.VectoredDatabase
	scratch     *hyperscan.Scratch
	err         error
}

var (
	ErrWorkerUninitialized = errors.New("worker uninitialized")
)

// NewConcurrentWorker returns a worker
func NewConcurrentWorker(requestChan chan concurrentScanRequest, stopChan chan struct{}) *ConcurrentWorker {
	return &ConcurrentWorker{
		requestChan: requestChan,
		stopChan:    stopChan,
		refreshChan: make(chan hyperscan.VectoredDatabase),
		scratch:     nil,
		err:         ErrWorkerUninitialized,
	}
}

func (w *ConcurrentWorker) Start() {
	for {
		select {
		case request := <-w.requestChan:
			w.onScan(request)
		case newDB := <-w.refreshChan:
			w.onUpdateDB(newDB)
		case <-w.stopChan:
			w.onStop()
			return
		}
	}
}

func (w *ConcurrentWorker) onUpdateDB(newDB hyperscan.VectoredDatabase) {
	w.db = newDB
	switch w.scratch {
	case nil:
		w.scratch, w.err = hyperscan.NewScratch(w.db)
	default:
		w.err = w.scratch.Realloc(w.db)
	}
}

func (w *ConcurrentWorker) onScan(request concurrentScanRequest) {
	if w.err != nil {
		request.responseChan <- concurrentScanResponse{err: w.err}
		return
	}

	var response = concurrentScanResponse{
		matched: make([]uint, 0),
		err:     nil,
	}
	response.err = w.db.Scan(
		request.blocks,
		w.scratch,
		func(id uint, from, to uint64, flags uint, context interface{}) error {
			var matched = context.(*[]uint)

			*matched = append(*matched, id)
			return nil
		},
		&response.matched)

	request.responseChan <- response
}

func (w *ConcurrentWorker) onStop() {
	w.scratch.Free()
}

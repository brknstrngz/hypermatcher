package hypermatcher

import "github.com/flier/gohs/hyperscan"

// PoolWorker is a scanning worker
type PoolWorker struct {
	stopChan    chan struct{}
	requestChan chan concurrentScanRequest
	refreshChan chan hyperscan.VectoredDatabase
	db          hyperscan.VectoredDatabase
	scratch     *hyperscan.Scratch
	err         error
}

// NewPoolWorker returns a worker
func NewPoolWorker(requestChan chan concurrentScanRequest, stopChan chan struct{}) *PoolWorker {
	return &PoolWorker{
		requestChan: requestChan,
		stopChan:    stopChan,
		refreshChan: make(chan hyperscan.VectoredDatabase),
		scratch:     nil,
		err:         ErrWorkerUninitialized,
	}
}

func (w *PoolWorker) Start() {
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

func (w *PoolWorker) onUpdateDB(newDB hyperscan.VectoredDatabase) {
	w.db = newDB
	switch w.scratch {
	case nil:
		w.scratch, w.err = hyperscan.NewScratch(w.db)
	default:
		w.err = w.scratch.Realloc(w.db)
	}
}

func (w *PoolWorker) onScan(request concurrentScanRequest) {
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
		matchHandler,
		&response.matched)

	request.responseChan <- response
}

func (w *PoolWorker) onStop() {
	w.scratch.Free()
}

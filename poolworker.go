package hypermatcher

import "github.com/flier/gohs/hyperscan"

// PoolWorker is a matching worker
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

func (pw *PoolWorker) Start() {
	for {
		select {
		case request := <-pw.requestChan:
			pw.onScan(request)
		case newDB := <-pw.refreshChan:
			pw.onUpdateDB(newDB)
		case <-pw.stopChan:
			pw.onStop()
			return
		}
	}
}

func (pw *PoolWorker) onUpdateDB(newDB hyperscan.VectoredDatabase) {
	pw.db = newDB
	switch pw.scratch {
	case nil:
		pw.scratch, pw.err = hyperscan.NewScratch(pw.db)
	default:
		pw.err = pw.scratch.Realloc(pw.db)
	}
}

func (pw *PoolWorker) onScan(request concurrentScanRequest) {
	if pw.err != nil {
		request.responseChan <- concurrentScanResponse{err: pw.err}
		return
	}

	var response = concurrentScanResponse{
		matched: make([]uint, 0),
		err:     nil,
	}
	response.err = pw.db.Scan(
		request.blocks,
		pw.scratch,
		matchHandler,
		&response.matched)

	request.responseChan <- response
}

func (pw *PoolWorker) onStop() {
	pw.scratch.Free()
}

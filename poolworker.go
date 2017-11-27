package hypermatcher

import "github.com/flier/gohs/hyperscan"

// poolWorker is a matching worker
type poolWorker struct {
	stopChan    chan struct{}
	requestChan chan concurrentScanRequest
	refreshChan chan hyperscan.VectoredDatabase
	db          hyperscan.VectoredDatabase
	scratch     *hyperscan.Scratch
	err         error
}

// newPoolWorker returns a worker
func newPoolWorker(requestChan chan concurrentScanRequest, stopChan chan struct{}) *poolWorker {
	return &poolWorker{
		requestChan: requestChan,
		stopChan:    stopChan,
		refreshChan: make(chan hyperscan.VectoredDatabase),
		scratch:     nil,
		err:         ErrWorkerUninitialized,
	}
}

func (pw *poolWorker) start() {
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

func (pw *poolWorker) onUpdateDB(newDB hyperscan.VectoredDatabase) {
	pw.db = newDB
	switch pw.scratch {
	case nil:
		pw.scratch, pw.err = hyperscan.NewScratch(pw.db)
	default:
		pw.err = pw.scratch.Realloc(pw.db)
	}
}

func (pw *poolWorker) onScan(request concurrentScanRequest) {
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

func (pw *poolWorker) onStop() {
	pw.scratch.Free()
}

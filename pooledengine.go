package hyperscanner

import (
	"fmt"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// PooledEngine is a concurrent hypermatcher.Engine implementation
// backed by a pool of goroutines with individual scratch space
type PooledEngine struct {
	requestChan chan concurrentScanRequest
	stopChan    chan struct{}
	workers     []*PoolWorker
	patterns    []*hyperscan.Pattern
	db          hyperscan.VectoredDatabase
	loaded      bool
	started     bool
	mu          sync.RWMutex
}

type concurrentScanRequest struct {
	blocks       [][]byte
	responseChan chan concurrentScanResponse
}

type concurrentScanResponse struct {
	matched []uint
	err     error
}

// NewPooledEngine returns a PooledEngine
func NewPooledEngine(numWorkers int) *PooledEngine {
	return &PooledEngine{
		requestChan: make(chan concurrentScanRequest),
		stopChan:    make(chan struct{}),
		workers:     make([]*PoolWorker, numWorkers),
		patterns:    make([]*hyperscan.Pattern, 0),
		loaded:      false,
		started:     false,
		mu:          sync.RWMutex{},
	}
}

// Update re-initializes the pattern database used by the
// scanner, returning an error if any of them fails to parse
func (ce *PooledEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return ErrNoPatterns
	}

	// do not update the pattern database if the workers are not running - that would block
	var started bool
	ce.mu.RLock()
	started = ce.started
	ce.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}

	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var db, compiledPatterns, dbErr = compilePatterns(patterns)
	if dbErr != nil {
		return fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	// if a previous database already exists, close it first
	ce.mu.Lock()
	if ce.loaded {
		ce.db.Close()
	}
	ce.db = db
	ce.patterns = compiledPatterns
	ce.loaded = true
	ce.mu.Unlock()
	// send the new database to the workers
	for _, worker := range ce.workers {
		worker.refreshChan <- ce.db
	}

	return nil
}

// Match takes a vectored byte corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (ce *PooledEngine) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded or started, return an error
	ce.mu.RLock()
	var loaded, started = ce.loaded, ce.started
	ce.mu.RUnlock()
	switch {
	case !loaded:
		return nil, ErrDBNotLoaded
	case !started:
		return nil, ErrNotStarted
	}

	// attempt to send the scan request in non-blocking
	// mode, returning an error if all workers are busy
	// the response is read from a per-request channel
	var request = concurrentScanRequest{
		blocks:       corpus,
		responseChan: make(chan concurrentScanResponse),
	}
	var response = concurrentScanResponse{
		matched: make([]uint, 0),
	}
	select {
	case ce.requestChan <- request: // request sent, must wait for response
		response = <-request.responseChan
	default:
		return nil, ErrBusy
	}
	if response.err != nil {
		return nil, response.err
	}

	// response.matched contains indices of matched expressions. each
	// index can appear more than once as every expression can match
	// several of the input strings, so we aggregate them here
	return matchedIdxToStrings(response.matched, ce.patterns, &ce.mu), nil
}

// Match takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (ce *PooledEngine) MatchStrings(corpus []string) ([]string, error) {
	return ce.Match(stringsToBytes(corpus))
}

// Start starts the workers backing the concurrent engine
func (ce *PooledEngine) Start() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.started {
		return ErrStarted
	}

	for idx := range ce.workers {
		ce.workers[idx] = NewPoolWorker(ce.requestChan, ce.stopChan)
		go ce.workers[idx].Start()
	}

	ce.started = true

	return nil
}

// Stop stops the workers backing the concurrent engine
func (ce *PooledEngine) Stop() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if !ce.started {
		return ErrNotStarted
	}

	// close stopChan, signaling workers to stop
	close(ce.stopChan)

	// close the database if it is loaded
	if ce.loaded {
		ce.db.Close()
		ce.loaded = false
	}

	ce.started = false

	return nil
}

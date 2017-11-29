package hypermatcher

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
	workers     []*poolWorker
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
		workers:     make([]*poolWorker, numWorkers),
		patterns:    make([]*hyperscan.Pattern, 0),
		loaded:      false,
		started:     false,
		mu:          sync.RWMutex{},
	}
}

// Update re-initializes the pattern database used by the
// scanner, returning an error if any of them fails to parse
func (pe *PooledEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return ErrNoPatterns
	}

	// do not update the pattern database if the workers are not running - that would block
	var started bool
	pe.mu.RLock()
	started = pe.started
	pe.mu.RUnlock()
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
	pe.mu.Lock()
	if pe.loaded {
		pe.db.Close()
	}
	pe.db = db
	pe.patterns = compiledPatterns
	pe.loaded = true
	pe.mu.Unlock()
	// send the new database to the workers
	for _, worker := range pe.workers {
		worker.refreshChan <- pe.db
	}

	return nil
}

// Match takes a vectored byte corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (pe *PooledEngine) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded or started, return an error
	pe.mu.RLock()
	var loaded, started = pe.loaded, pe.started
	pe.mu.RUnlock()
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
	case pe.requestChan <- request: // request sent, must wait for response
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
	return matchedIdxToStrings(response.matched, pe.patterns, &pe.mu), nil
}

// MatchStrings takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (pe *PooledEngine) MatchStrings(corpus []string) ([]string, error) {
	return pe.Match(stringsToBytes(corpus))
}

// Start starts the workers backing the concurrent engine
func (pe *PooledEngine) Start() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if pe.started {
		return ErrStarted
	}

	for idx := range pe.workers {
		pe.workers[idx] = newPoolWorker(pe.requestChan, pe.stopChan)
		go pe.workers[idx].start()
	}

	pe.started = true

	return nil
}

// Stop stops the workers backing the concurrent engine
func (pe *PooledEngine) Stop() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if !pe.started {
		return ErrNotStarted
	}

	// close stopChan, signaling workers to stop
	close(pe.stopChan)

	// close the database if it is loaded
	if pe.loaded {
		pe.db.Close()
		pe.loaded = false
	}

	pe.started = false

	return nil
}

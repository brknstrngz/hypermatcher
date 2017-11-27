package hyperscanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// ConcurrentEngine is a concurrent hyperscanner.Engine implementation
// backed by a pool of goroutines with individual scratch space
type ConcurrentEngine struct {
	requestChan chan concurrentScanRequest
	stopChan    chan struct{}
	workers     []*ConcurrentWorker
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

var (
	ErrStarted     = errors.New("workers already started")
	ErrNotStarted  = errors.New("workers not started")
	ErrDBNotLoaded = errors.New("database not loaded")
	ErrBusy        = errors.New("workers busy")
)

// NewConcurrentEngine returns a ConcurrentEngine
func NewConcurrentEngine(numWorkers int) *ConcurrentEngine {
	return &ConcurrentEngine{
		requestChan: make(chan concurrentScanRequest),
		stopChan:    make(chan struct{}),
		workers:     make([]*ConcurrentWorker, numWorkers),
		patterns:    make([]*hyperscan.Pattern, 0),
		loaded:      false,
		started:     false,
		mu:          sync.RWMutex{},
	}
}

// Update re-initializes the pattern database used by the
// scanner, returning an error if any of them fails to parse
func (cs *ConcurrentEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return errors.New("error updating pattern database: patterns array cannot be empty")
	}

	// do not update the pattern database if the workers are not running - that would block
	var started bool
	cs.mu.RLock()
	started = cs.started
	cs.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}

	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var compiledPatterns = make([]*hyperscan.Pattern, len(patterns))
	for idx, pattern := range patterns {
		var compiledPattern, compileErr = hyperscan.ParsePattern(pattern)
		if compileErr != nil {
			return fmt.Errorf("error parsing pattern %s: %s", pattern, compileErr.Error())
		}

		compiledPattern.Id = idx
		compiledPatterns[idx] = compiledPattern
	}

	// initialize a new database with the new patterns
	var db, dbErr = hyperscan.NewVectoredDatabase(compiledPatterns...)
	if dbErr != nil {
		return fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	// if a previous database already exists, close it first
	cs.mu.Lock()
	if cs.loaded {
		cs.db.Close()
	}
	cs.db = db
	cs.patterns = compiledPatterns
	cs.loaded = true
	cs.mu.Unlock()
	// send the new database to the workers
	for _, worker := range cs.workers {
		worker.refreshChan <- cs.db
	}

	return nil
}

// Scan takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (cs *ConcurrentEngine) Scan(corpus []string) ([]string, error) {
	// if the database has not yet been loaded or started, return an error
	cs.mu.RLock()
	var loaded, started = cs.loaded, cs.started
	cs.mu.RUnlock()
	switch {
	case !loaded:
		return nil, ErrDBNotLoaded
	case !started:
		return nil, ErrNotStarted
	}

	// change the corpus representation from string to []byte
	var corpusBlocks = make([][]byte, len(corpus))
	for idx, corpusElement := range corpus {
		corpusBlocks[idx] = stringToByteSlice(corpusElement)
	}

	// attempt to send the scan request in non-blocking
	// mode, returning an error if all workers are busy
	// the response is read from a per-request channel
	var request = concurrentScanRequest{
		blocks:       corpusBlocks,
		responseChan: make(chan concurrentScanResponse),
	}
	var response concurrentScanResponse
	select {
	case cs.requestChan <- request: // request sent, must wait for response
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
	var matchedSieve = make(map[uint]struct{}, 0)
	for _, patIdx := range response.matched {
		matchedSieve[patIdx] = struct{}{}
	}
	var matchedPatterns = make([]string, len(matchedSieve))
	cs.mu.RLock()
	for patternsIdx := range matchedSieve {
		matchedPatterns[patternsIdx] = cs.patterns[patternsIdx].Expression.String()
	}
	cs.mu.RUnlock()

	return matchedPatterns, nil
}

// Start starts the workers backing the concurrent engine
func (cs *ConcurrentEngine) Start() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.started {
		return ErrStarted
	}

	for idx := range cs.workers {
		cs.workers[idx] = NewConcurrentWorker(cs.requestChan, cs.stopChan)
		go cs.workers[idx].Start()
	}

	cs.started = true

	return nil
}

// Stop stops the workers backing the concurrent engine
func (cs *ConcurrentEngine) Stop() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.started {
		return ErrNotStarted
	}

	// close stopChan, signalling workers to stop
	close(cs.stopChan)

	// close the database if it is loaded
	if cs.loaded {
		cs.db.Close()
		cs.loaded = false
	}

	cs.started = false

	return nil
}

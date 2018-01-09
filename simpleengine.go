package hypermatcher

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/flier/gohs/hyperscan"
)

// SimpleEngine is a basic Engine implementation with a single hyperscan.Scratch protected by a mutex
type SimpleEngine struct {
	patterns []*hyperscan.Pattern
	db       hyperscan.VectoredDatabase
	scratch  *hyperscan.Scratch
	loaded   uint32
	mu       sync.RWMutex
}

// NewSimpleEngine returns a SimpleEngine instance
func NewSimpleEngine() *SimpleEngine {
	return &SimpleEngine{
		patterns: make([]*hyperscan.Pattern, 0),
		mu:       sync.RWMutex{},
	}
}

// Update rebuilds the pattern database, returning an optional error
func (se *SimpleEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return ErrNoPatterns
	}

	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var compiledPatterns, compileErr = compilePatterns(patterns)
	if compileErr != nil {
		return fmt.Errorf("error updating pattern database: %s", compileErr.Error())
	}

	// build the pattern database
	var newDB, dbErr = buildDatabase(compiledPatterns)
	if dbErr != nil {
		return fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	// allocate new scratch space
	var newScratch, scratchErr = hyperscan.NewScratch(newDB)
	if scratchErr != nil {
		return fmt.Errorf("error updating pattern database: %s", scratchErr.Error())
	}

	se.mu.Lock()
	if se.isLoaded() {
		se.db.Close()
	}
	se.db = newDB
	se.patterns = compiledPatterns
	if se.scratch != nil {
		se.scratch.Free()
	}
	se.scratch = newScratch
	se.setLoaded()
	se.mu.Unlock()

	return nil
}

// Match takes a vectored byte corpus and returns a slice of patterns that matched the corpus and an optional error
func (se *SimpleEngine) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded, return an error
	if !se.isLoaded() {
		return nil, ErrNotLoaded
	}

	var matched = make(map[uint]struct{}, 0)
	// we take a write lock as se.scratch is written to
	se.mu.Lock()
	var scanErr = se.db.Scan(
		corpus,
		se.scratch,
		matchHandler,
		&matched)
	if scanErr != nil {
		se.mu.Unlock()
		return nil, scanErr
	}
	se.mu.Unlock()

	// response.matched contains indices of matched expressions. each
	// index can appear more than once as every expression can match
	// several of the input strings, so we aggregate them here. we hold
	// a read lock on se.patterns in case Update() is called during aggregation
	se.mu.RLock()
	var ret = matchedIdxToStrings(matched, se.patterns)
	se.mu.RUnlock()

	return ret, nil
}

// MatchStrings takes a vectored string corpus and returns a slice of patterns that matched the corpus and an optional error
func (se *SimpleEngine) MatchStrings(corpus []string) ([]string, error) {
	return se.Match(stringsToBytes(corpus))
}

func (se *SimpleEngine) isLoaded() bool {
	return atomic.LoadUint32(&se.loaded) == 1
}

func (se *SimpleEngine) setLoaded() {
	atomic.StoreUint32(&se.loaded, 1)
}

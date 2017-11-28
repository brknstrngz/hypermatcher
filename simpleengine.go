package hypermatcher

import (
	"fmt"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// SimpleEngine is a simple hypermatcher.Engine implementation
// with a single hyperscan.Scratch protected by a mutex
type SimpleEngine struct {
	patterns []*hyperscan.Pattern
	db       hyperscan.VectoredDatabase
	scratch  *hyperscan.Scratch
	loaded   bool
	mu       sync.RWMutex
}

// NewSimpleEngine returns a SimpleEngine
func NewSimpleEngine() *SimpleEngine {
	return &SimpleEngine{
		patterns: make([]*hyperscan.Pattern, 0),
		scratch:  nil,
		loaded:   false,
		mu:       sync.RWMutex{},
	}
}

// Update re-initializes the pattern database used by the
// scanner, returning an error if any of them fails to parse
func (se *SimpleEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return ErrNoPatterns
	}

	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var db, compiledPatterns, dbErr = compilePatterns(patterns)
	if dbErr != nil {
		return fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	se.mu.Lock()
	se.db = db
	se.patterns = compiledPatterns
	se.loaded = true
	var scratchErr error
	switch se.scratch {
	case nil:
		se.scratch, scratchErr = hyperscan.NewScratch(se.db)
	default:
		scratchErr = se.scratch.Realloc(se.db)
	}
	se.mu.Unlock()

	return scratchErr
}

// Match takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (se *SimpleEngine) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded, return an error
	se.mu.RLock()
	var loaded = se.loaded
	se.mu.RUnlock()
	if !loaded {
		return nil, ErrDBNotLoaded
	}

	var matched = make([]uint, 0)
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
	// several of the input strings, so we aggregate them here
	return matchedIdxToStrings(matched, se.patterns, &se.mu), nil
}

// Match takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (se *SimpleEngine) MatchStrings(corpus []string) ([]string, error) {
	return se.Match(stringsToBytes(corpus))
}
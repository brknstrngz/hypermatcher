package hyperscanner

import (
	"fmt"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// ConsecutiveEngine is a simple hyperscanner.Engine implementation
// with a single hyperscan.Scratch
type ConsecutiveEngine struct {
	patterns []*hyperscan.Pattern
	db       hyperscan.VectoredDatabase
	scratch  *hyperscan.Scratch
	loaded   bool
	mu       sync.RWMutex
}

// NewConsecutiveEngine returns a ConsecutiveEngine
func NewConsecutiveEngine() *ConsecutiveEngine {
	return &ConsecutiveEngine{
		patterns: make([]*hyperscan.Pattern, 0),
		scratch:  nil,
		loaded:   false,
		mu:       sync.RWMutex{},
	}
}

// Update re-initializes the pattern database used by the
// scanner, returning an error if any of them fails to parse
func (ce *ConsecutiveEngine) Update(patterns []string) error {
	if len(patterns) == 0 {
		return ErrNoPatterns
	}

	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var db, compiledPatterns, dbErr = compilePatterns(patterns)
	if dbErr != nil {
		return fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	ce.mu.Lock()
	ce.db = db
	ce.patterns = compiledPatterns
	ce.loaded = true
	var scratchErr error
	switch ce.scratch {
	case nil:
		ce.scratch, scratchErr = hyperscan.NewScratch(ce.db)
	default:
		scratchErr = ce.scratch.Realloc(ce.db)
	}
	ce.mu.Unlock()

	return scratchErr
}

// Match takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (ce *ConsecutiveEngine) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded, return an error
	ce.mu.RLock()
	var loaded = ce.loaded
	ce.mu.RUnlock()
	if !loaded {
		return nil, ErrDBNotLoaded
	}

	var matched = make([]uint, 0)
	ce.mu.Lock()
	var scanErr = ce.db.Scan(
		corpus,
		ce.scratch,
		matchHandler,
		&matched)
	if scanErr != nil {
		ce.mu.Unlock()
		return nil, scanErr
	}
	ce.mu.Unlock()

	// response.matched contains indices of matched expressions. each
	// index can appear more than once as every expression can match
	// several of the input strings, so we aggregate them here
	var matchedSieve = make(map[uint]struct{}, 0)
	for _, patIdx := range matched {
		matchedSieve[patIdx] = struct{}{}
	}
	var matchedPatterns = make([]string, len(matchedSieve))
	ce.mu.RLock()
	for patternsIdx := range matchedSieve {
		matchedPatterns[patternsIdx] = ce.patterns[patternsIdx].Expression.String()
	}
	ce.mu.RUnlock()

	return matchedPatterns, nil
}

// Match takes a vectored string corpus and returns a list of strings
// representing patterns that matched the corpus and an optional error
func (ce *ConsecutiveEngine) MatchStrings(corpus []string) ([]string, error) {
	return ce.Match(stringsToBytes(corpus))
}

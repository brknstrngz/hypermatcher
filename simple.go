package hypermatcher

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/flier/gohs/hyperscan"
)

// Simple is a basic Engine/Database implementation with a single hyperscan.Scratch protected by a mutex
type Simple struct {
	patterns []*hyperscan.Pattern
	db       hyperscan.VectoredDatabase
	scratch  *hyperscan.Scratch
	loaded   uint32
	mu       sync.RWMutex
}

// NewSimple returns a Simple instance
func NewSimple() *Simple {
	return &Simple{
		patterns: make([]*hyperscan.Pattern, 0),
		mu:       sync.RWMutex{},
	}
}

// Update rebuilds the pattern database, returning an optional error
func (s *Simple) Update(patterns []string) error {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isLoaded() {
		s.db.Close()
	}
	s.db = newDB
	s.patterns = compiledPatterns
	if s.scratch != nil {
		s.scratch.Free()
		s.scratch = nil
	}
	s.scratch = newScratch
	s.setLoaded()

	return nil
}

// Close releases all resources used by the database, returning an optional error
func (s *Simple) Close() error {
	if !s.isLoaded() {
		return ErrNotLoaded
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.db.Close(); err != nil {
		return err
	}

	if s.scratch != nil {
		s.scratch.Free()
		s.scratch = nil
	}
	s.setUnloaded()

	return nil
}

// Match takes a vectored byte corpus and returns a slice of patterns that matched the corpus and an optional error
func (s *Simple) Match(corpus [][]byte) ([]string, error) {
	// if the database has not yet been loaded, return an error
	if !s.isLoaded() {
		return nil, ErrNotLoaded
	}

	var matched = make(map[uint]struct{}, 0)
	// we take a write lock as s.scratch is written to
	s.mu.Lock()
	var scanErr = s.db.Scan(
		corpus,
		s.scratch,
		matchHandler,
		&matched)
	if scanErr != nil {
		s.mu.Unlock()
		return nil, scanErr
	}

	// response.matched contains indices of matched expressions. each
	// index can appear more than once as every expression can match
	// several of the input strings, so we aggregate them here
	var matchedPatterns = matchedIdxToPatterns(matched, s.patterns)
	s.mu.Unlock()

	return matchedPatterns, nil
}

// MatchStrings takes a vectored string corpus and returns a slice of patterns that matched the corpus and an optional error
func (s *Simple) MatchStrings(corpus []string) ([]string, error) {
	return s.Match(stringsToByteSlices(corpus))
}

func (s *Simple) isLoaded() bool {
	return atomic.LoadUint32(&s.loaded) == 1
}

func (s *Simple) setLoaded() {
	atomic.StoreUint32(&s.loaded, 1)
}

func (s *Simple) setUnloaded() {
	atomic.StoreUint32(&s.loaded, 0)
}

func compilePatterns(patterns []string) ([]*hyperscan.Pattern, error) {
	// pattern compilation runs concurrently with sizable speedup: each
	// compiled pattern is added to the compiledPatterns slice  on success
	// or an error is added to the compileErrors slice on  failure; as
	// goroutines operate on different ranges of the input slice, we do not
	// need locking
	var wg sync.WaitGroup
	var compiledPatterns = make([]*hyperscan.Pattern, len(patterns))
	var compileErrors = make([]error, len(patterns))
	var patternRanges = subSlices(compiledPatterns, runtime.NumCPU())
	for _, patternRange := range patternRanges {
		wg.Add(1)
		go func(patternSet [2]int) {
		breakLoop:
			for idx := patternSet[0]; idx < patternSet[1]; idx++ {
				var compiledPattern, compileErr = hyperscan.ParsePattern(patterns[idx])
				switch compileErr {
				case nil:
					compiledPattern.Id = idx
					compiledPatterns[idx] = compiledPattern
				default:
					compileErrors[idx] = compileErr
					break breakLoop
				}
			}
			wg.Done()
		}(patternRange)
	}
	wg.Wait()

	// check for errors, returning the first one found
	for _, compileError := range compileErrors {
		if compileError != nil {
			return nil, compileError
		}
	}

	return compiledPatterns, nil
}

func buildDatabase(patterns []*hyperscan.Pattern) (hyperscan.VectoredDatabase, error) {
	// initialize a new database with the new patterns
	var builder = &hyperscan.DatabaseBuilder{
		Patterns: patterns,
		Mode:     hyperscan.VectoredMode,
		Platform: hyperscan.PopulatePlatform(),
	}
	var db, err = builder.Build()
	if err != nil {
		return nil, fmt.Errorf("error updating pattern database: %s", err.Error())
	}

	return db.(hyperscan.VectoredDatabase), nil
}

var matchHandler = func(id uint, from, to uint64, flags uint, context interface{}) error {
	(*(context.(*map[uint]struct{})))[id] = struct{}{}

	return nil
}

func matchedIdxToPatterns(matched map[uint]struct{}, patterns []*hyperscan.Pattern) []string {
	var matchedPatterns = make([]string, len(matched))
	for patternsIdx := range matched {
		matchedPatterns[patternsIdx] = patterns[patternsIdx].Expression.String()
	}

	return matchedPatterns
}

func stringsToByteSlices(corpus []string) [][]byte {
	var corpusBlocks = make([][]byte, len(corpus))
	for idx, corpusElement := range corpus {
		corpusBlocks[idx] = stringToByteSlice(corpusElement)
	}

	return corpusBlocks
}

// naughty zero copy string to []byte conversion
func stringToByteSlice(input string) []byte {
	var stringHeader = (*reflect.StringHeader)(unsafe.Pointer(&input))
	var sliceHeader = reflect.SliceHeader{
		Data: stringHeader.Data,
		Len:  stringHeader.Len,
		Cap:  stringHeader.Len,
	}

	return *(*[]byte)(unsafe.Pointer(&sliceHeader))
}

func subSlices(slice []*hyperscan.Pattern, numSlices int) [][2]int {
	var numPerSlice = len(slice) / numSlices
	var splitIndices = make([][2]int, 0)

	for i := 0; i < numSlices; i++ {
		splitIndices = append(splitIndices, [2]int{i * numPerSlice, (i + 1) * numPerSlice})
	}

	if numSlices*numPerSlice < len(slice) {
		splitIndices = append(splitIndices, [2]int{numSlices * numPerSlice, len(slice)})
	}

	return splitIndices
}

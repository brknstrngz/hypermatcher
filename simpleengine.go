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
	var matchedPatterns = matchedIdxToPatterns(matched, se.patterns)
	se.mu.RUnlock()

	return matchedPatterns, nil
}

// MatchStrings takes a vectored string corpus and returns a slice of patterns that matched the corpus and an optional error
func (se *SimpleEngine) MatchStrings(corpus []string) ([]string, error) {
	return se.Match(stringsToByteSlices(corpus))
}

func (se *SimpleEngine) isLoaded() bool {
	return atomic.LoadUint32(&se.loaded) == 1
}

func (se *SimpleEngine) setLoaded() {
	atomic.StoreUint32(&se.loaded, 1)
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

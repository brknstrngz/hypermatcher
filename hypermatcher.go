package hypermatcher

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"unsafe"

	"github.com/flier/gohs/hyperscan"
)

var (
	// ErrNotLoaded is returned when Match() is invoked while the pattern database is not compiled and loaded
	ErrNotLoaded = errors.New("database not loaded")
	// ErrNoPatterns is returned when Update() is invoked with an empty pattern slice
	ErrNoPatterns = errors.New("no patterns specified")
)

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
	var matched = context.(*[]uint)
	*matched = append(*matched, id)

	return nil
}

func matchedIdxToStrings(matched []uint, patterns []*hyperscan.Pattern) []string {
	var matchedSieve = make(map[uint]struct{}, 0)
	for _, patIdx := range matched {
		matchedSieve[patIdx] = struct{}{}
	}

	var matchedPatterns = make([]string, len(matchedSieve))
	var matchPatternsIdx int
	for patternsIdx := range matchedSieve {
		matchedPatterns[matchPatternsIdx] = patterns[patternsIdx].Expression.String()
		matchPatternsIdx++
	}

	return matchedPatterns
}

func stringsToBytes(corpus []string) [][]byte {
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

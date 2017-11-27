package hyperscanner

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/flier/gohs/hyperscan"
)

var (
	ErrStarted             = errors.New("workers already started")
	ErrNotStarted          = errors.New("workers not started")
	ErrDBNotLoaded         = errors.New("database not loaded")
	ErrBusy                = errors.New("workers busy")
	ErrNoPatterns          = errors.New("no patterns specified")
	ErrWorkerUninitialized = errors.New("worker uninitialized")
)

func compilePatterns(patterns []string) (hyperscan.VectoredDatabase, []*hyperscan.Pattern, error) {
	// compile patterns and add them to the internal list, returning
	// an error on the first pattern that fails to parse
	var compiledPatterns = make([]*hyperscan.Pattern, len(patterns))
	for idx, pattern := range patterns {
		var compiledPattern, compileErr = hyperscan.ParsePattern(pattern)
		if compileErr != nil {
			return nil, nil, fmt.Errorf("error parsing pattern %s: %s", pattern, compileErr.Error())
		}

		compiledPattern.Id = idx
		compiledPatterns[idx] = compiledPattern
	}

	// initialize a new database with the new patterns
	var db, dbErr = hyperscan.NewVectoredDatabase(compiledPatterns...)
	if dbErr != nil {
		return nil, nil, fmt.Errorf("error updating pattern database: %s", dbErr.Error())
	}

	return db, compiledPatterns, nil
}

var matchHandler = func(id uint, from, to uint64, flags uint, context interface{}) error {
	var matched = context.(*[]uint)
	*matched = append(*matched, id)

	return nil
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

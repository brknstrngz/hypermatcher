package hypermatcher

import "errors"

// Database is a database of compiled hyperscan patterns
type Database interface {
	// Update rebuilds the pattern database, returning an optional error
	Update(patterns []string) error
	// Close releases all resources used by the database, returning an optional error
	Close() error
}

// Engine is the hyperscan pattern matching interface
type Engine interface {
	// Match takes a vectored byte corpus and returns a slice of patterns that matched the corpus and an optional error
	Match(corpus [][]byte) ([]string, error)
	// MatchStrings takes a vectored string corpus and returns a slice of patterns that matched the corpus and an optional error
	MatchStrings(corpus []string) ([]string, error)
}

var (
	// ErrNotLoaded is returned when Match() is invoked while the pattern database is not compiled and loaded
	ErrNotLoaded = errors.New("database not loaded")
	// ErrNoPatterns is returned when Update() is invoked with an empty pattern slice
	ErrNoPatterns = errors.New("no patterns specified")
)

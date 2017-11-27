package hyperscanner

// Engine is the hyperscanner pattern matching interface
type Engine interface {
	// Update rebuilds the pattern database, returning an optional error
	Update(patterns []string) error
	// Scan takes a vectored string corpus and returns a list of strings
	// representing patterns that matched the corpus and an optional error
	Scan(corpus []string) ([]string, error)
}

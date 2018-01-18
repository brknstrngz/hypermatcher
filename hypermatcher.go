package hypermatcher

import "errors"

var (
	// ErrNotLoaded is returned when Match() is invoked while the pattern database is not compiled and loaded
	ErrNotLoaded = errors.New("database not loaded")
	// ErrNoPatterns is returned when Update() is invoked with an empty pattern slice
	ErrNoPatterns = errors.New("no patterns specified")
)

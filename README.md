# hypermatcher
--
    import "github.com/vgalu/hypermatcher"


## Usage

```go
var (
	ErrNotLoaded  = errors.New("database not loaded")
	ErrNoPatterns = errors.New("no patterns specified")
)
```

#### type Engine

```go
type Engine interface {
	// Update rebuilds the pattern database, returning an optional error
	Update(patterns []string) error
	// Match takes a vectored byte corpus and returns a list of strings
	// representing patterns that matched the corpus and an optional error
	Match(corpus [][]byte) ([]string, error)
	// Match takes a vectored string corpus and returns a list of strings
	// representing patterns that matched the corpus and an optional error
	MatchStrings(corpus []string) ([]string, error)
}
```

Engine is the hyperscanner pattern matching interface

#### type SimpleEngine

```go
type SimpleEngine struct {
}
```

SimpleEngine is a simple hypermatcher.Engine implementation with a single
hyperscan.Scratch protected by a mutex

#### func  NewSimpleEngine

```go
func NewSimpleEngine() *SimpleEngine
```
NewSimpleEngine returns a SimpleEngine

#### func (*SimpleEngine) Match

```go
func (se *SimpleEngine) Match(corpus [][]byte) ([]string, error)
```
Match takes a vectored string corpus and returns a list of strings representing
patterns that matched the corpus and an optional error

#### func (*SimpleEngine) MatchStrings

```go
func (se *SimpleEngine) MatchStrings(corpus []string) ([]string, error)
```
MatchStrings takes a vectored string corpus and returns a list of strings
representing patterns that matched the corpus and an optional error

#### func (*SimpleEngine) Update

```go
func (se *SimpleEngine) Update(patterns []string) error
```
Update re-initializes the pattern database used by the scanner, returning an
error if any of them fails to parse

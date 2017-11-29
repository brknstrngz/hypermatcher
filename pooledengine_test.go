package hypermatcher

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func Test_PooledEngineUpdatePatterns(t *testing.T) {
	t.Parallel()

	var warmUpTime = time.Millisecond
	var tests = []struct {
		name      string
		engineGen func() *PooledEngine
		patterns  []string
		wantErr   error
	}{
		{"Empty pattern list",
			func() *PooledEngine {
				return NewPooledEngine(runtime.NumCPU())
			},
			nil,
			errors.New("no patterns specified"),
		},
		{
			"Workers not started",
			func() *PooledEngine {
				return NewPooledEngine(runtime.NumCPU())
			},
			[]string{"/pattern/"},
			errors.New("workers not started"),
		},
		{
			"Invalid pattern flag",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()

				return engine
			},
			[]string{"/pattern/z"},
			errors.New("error updating pattern database: error parsing pattern /pattern/z: invalid pattern, unknown flag `z`"),
		},
		{
			"Engine initializes successfully",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"/pattern/"},
			nil,
		},
	}

	for _, tt := range tests {
		var engine = tt.engineGen()
		var err = engine.Update(tt.patterns)
		engine.Stop()

		if !reflect.DeepEqual(err, tt.wantErr) {
			t.Errorf("%s got: %v, want: %v", tt.name, err, tt.wantErr)
		}
	}
}

func Test_PooledEngineMatch(t *testing.T) {
	t.Parallel()

	var warmUpTime = time.Millisecond
	var tests = []struct {
		name        string
		engineGen   func() *PooledEngine
		corpus      []string
		wantMatches []string
		wantErr     error
	}{
		{"Patterns not loaded",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpus"},
			nil,
			errors.New("database not loaded"),
		},
		{
			"Match not found",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/someotherkeyword/"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpus"},
			[]string{},
			nil,
		},
		{
			"Exact match found",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/corpus/"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpus"},
			[]string{"corpus"},
			nil,
		},
		{
			"Case insensitive match found",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/cOrPuS/i"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpus"},
			[]string{"cOrPuS"},
			nil,
		},
		{
			"Multiple matches found",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/cOrPuS/i", "/pus/i"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpus"},
			[]string{"cOrPuS", "pus"},
			nil,
		},
		{
			"Front anchored expression does not match",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/^cOrPuS/i"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"somethingnotstartingwithcorpus"},
			[]string{},
			nil,
		},
		{
			"Back anchored expression does not match",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/cOrPuS$/i"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"corpusgoesfirst"},
			[]string{},
			nil,
		},
		{
			"Anchored expression does not match",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/^cOrPuS$/i"})
				time.Sleep(warmUpTime)

				return engine
			},
			[]string{"somethingfirstthencorpusafter"},
			[]string{},
			nil,
		},
		{
			"Workers busy",
			func() *PooledEngine {
				var engine = NewPooledEngine(runtime.NumCPU())
				engine.Start()
				engine.Update([]string{"/^cOrPuS$/i"})

				return engine
			},
			[]string{"somethingfirstthencorpusafter"},
			nil,
			errors.New("workers busy"),
		},
	}

	for _, tt := range tests {
		var engine = tt.engineGen()
		var matches, err = engine.MatchStrings(tt.corpus)
		engine.Stop()

		if !reflect.DeepEqual(matches, tt.wantMatches) {
			t.Errorf("%s got: %#v, want: %#v", tt.name, matches, tt.wantMatches)
		}

		if !reflect.DeepEqual(err, tt.wantErr) {
			t.Errorf("%s got: %#v, want: %#v", tt.name, err, tt.wantErr)
		}
	}
}

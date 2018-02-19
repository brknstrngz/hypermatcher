package hypermatcher

import (
	"errors"
	"reflect"
	"testing"
)

func Test_SimpleEngineUpdatePatterns(t *testing.T) {
	t.Parallel()

	var engine = NewSimple()
	var tests = []struct {
		name     string
		patterns []string
		wantErr  error
	}{
		{"Empty pattern list",
			nil,
			errors.New("no patterns specified"),
		},
		{
			"Invalid pattern flag",
			[]string{"/pattern/z"},
			errors.New("error updating pattern database: invalid pattern, unknown flag `z`"),
		},
	}

	for _, tt := range tests {
		var err = engine.Update(tt.patterns)

		if !reflect.DeepEqual(err, tt.wantErr) {
			t.Errorf("got: %v, want: %v", err, tt.wantErr)
		}
	}
}

func Test_SimpleEngineMatch(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name        string
		engineGen   func() *Simple
		corpus      []string
		wantMatches []string
		wantErr     error
	}{
		{"Patterns not loaded",
			func() *Simple {
				return NewSimple()
			},
			[]string{"corpus"},
			nil,
			errors.New("database not loaded"),
		},
		{
			"Match not found",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/someotherkeyword/"})

				return engine
			},
			[]string{"corpus"},
			[]string{},
			nil,
		},
		{
			"Exact match found",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/corpus/"})

				return engine
			},
			[]string{"corpus"},
			[]string{"corpus"},
			nil,
		},
		{
			"Case insensitive match found",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/cOrPuS/i"})

				return engine
			},
			[]string{"corpus"},
			[]string{"cOrPuS"},
			nil,
		},
		{
			"Multiple matches found",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/cOrPuS/i", "/pus/i"})

				return engine
			},
			[]string{"corpus"},
			[]string{"cOrPuS", "pus"},
			nil,
		},
		{
			"Front anchored expression does not match",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/^cOrPuS/i"})

				return engine
			},
			[]string{"somethingnotstartingwithcorpus"},
			[]string{},
			nil,
		},
		{
			"Back anchored expression does not match",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/cOrPuS$/i"})

				return engine
			},
			[]string{"corpusgoesfirst"},
			[]string{},
			nil,
		},
		{
			"Anchored expression does not match",
			func() *Simple {
				var engine = NewSimple()
				engine.Update([]string{"/^cOrPuS$/i"})

				return engine
			},
			[]string{"somethingfirstthencorpusafter"},
			[]string{},
			nil,
		},
	}

	for _, tt := range tests {
		var matches, err = tt.engineGen().MatchStrings(tt.corpus)

		if !reflect.DeepEqual(matches, tt.wantMatches) {
			t.Errorf("%s got: %#v, want: %#v", tt.name, matches, tt.wantMatches)
		}

		if !reflect.DeepEqual(err, tt.wantErr) {
			t.Errorf("%s got: %#v, want: %#v", tt.name, err, tt.wantErr)
		}
	}
}

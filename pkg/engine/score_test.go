package engine

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestComputePartialScoreDowngradesPerfectScore(t *testing.T) {
	result := ComputePartialScore(nil, []ModuleError{NewModuleError("headers", errors.New("connection refused"))})

	if !result.Partial {
		t.Fatal("expected partial result")
	}
	if result.Score != 60 {
		t.Fatalf("expected partial score cap at 60, got %d", result.Score)
	}
	if result.Grade != GradeC {
		t.Fatalf("expected grade C, got %s", result.Grade)
	}
}

func TestModuleErrorSerializesMessage(t *testing.T) {
	data, err := json.Marshal(NewModuleError("headers", errors.New("connection refused")))
	if err != nil {
		t.Fatal(err)
	}

	got := string(data)
	want := `{"module":"headers","error":"connection refused"}`
	if got != want {
		t.Fatalf("unexpected JSON:\nwant %s\ngot  %s", want, got)
	}
}

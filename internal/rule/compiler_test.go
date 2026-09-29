package rule

import (
	"strings"
	"testing"
)

func mk(id string, targets []string, transforms []string) Rule {
	return Rule{
		ID:         id,
		Name:       id,
		Enabled:    true,
		Phase:      PhaseRequest,
		Targets:    targets,
		Operator:   OpContains,
		Value:      "x",
		Transforms: transforms,
		Action:     ActionBlock,
		Score:      1,
		Severity:   SeverityHigh,
	}
}

func TestCompileGroupsByTargetAndTransforms(t *testing.T) {
	rules := []Rule{
		mk("a", []string{"query"}, []string{"url_decode", "lowercase"}),
		mk("b", []string{"query"}, []string{"url_decode", "lowercase"}),
		mk("c", []string{"query"}, []string{"lowercase"}),
		mk("d", []string{"body"}, []string{"url_decode", "lowercase"}),
	}
	cs, err := Compile(rules, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(cs.Groups))
	}
	var multi *TargetGroup
	for _, g := range cs.Groups {
		if g.Target.String() == "query" && len(g.Pipeline) == 2 {
			multi = g
		}
	}
	if multi == nil || len(multi.Matchers) != 2 {
		t.Fatalf("expected shared query group with 2 matchers, got %+v", multi)
	}
	if !cs.NeedBody {
		t.Error("body rule should set NeedBody")
	}
	if cs.RuleCount != 4 {
		t.Errorf("RuleCount=%d want 4", cs.RuleCount)
	}
}

func TestCompileSkipsDisabled(t *testing.T) {
	r := mk("a", []string{"query"}, nil)
	r.Enabled = false
	cs, err := Compile([]Rule{r}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cs.RuleCount != 0 || len(cs.Groups) != 0 {
		t.Fatalf("disabled rule should be skipped: %+v", cs)
	}
}

func TestCompileErrors(t *testing.T) {
	bad := mk("a", []string{"query"}, nil)
	bad.Operator = OpRegex
	bad.Value = "("
	if _, err := Compile([]Rule{bad}, 1); err == nil {
		t.Error("expected regex error")
	}

	dup := []Rule{mk("a", []string{"query"}, nil), mk("a", []string{"body"}, nil)}
	if _, err := Compile(dup, 1); err == nil {
		t.Error("expected duplicate id error")
	}

	noTarget := mk("a", nil, nil)
	if _, err := Compile([]Rule{noTarget}, 1); err == nil {
		t.Error("expected missing target error")
	}

	badPhase := mk("a", []string{"query"}, nil)
	badPhase.Phase = PhaseResponse
	if _, err := Compile([]Rule{badPhase}, 1); err == nil {
		t.Error("expected unsupported phase error")
	}
}

func TestValidateID(t *testing.T) {
	r := mk("Good_ID", []string{"query"}, nil)
	if err := Validate(&r); err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("expected id validation error, got %v", err)
	}
}

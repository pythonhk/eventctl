package canonical

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalizeSortsAndNormalizesIntegers(t *testing.T) {
	t.Parallel()

	got, err := Canonicalize([]byte(` { "z": -0, "a": [2, 1], "unicode": "😀" } `))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[2,1],"unicode":"😀","z":0}`
	if string(got) != want {
		t.Fatalf("Canonicalize() = %s, want %s", got, want)
	}
}

func TestCanonicalizeRejectsAmbiguousJSON(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"duplicate literal":   `{"a":1,"a":2}`,
		"duplicate escaped":   `{"a":1,"\u0061":2}`,
		"fraction":            `{"a":1.0}`,
		"exponent":            `{"a":1e2}`,
		"lone high surrogate": `{"a":"\ud800"}`,
		"lone low surrogate":  `{"a":"\udc00"}`,
		"trailing value":      `{} {}`,
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Canonicalize([]byte(input)); err == nil {
				t.Fatalf("Canonicalize(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestStrictUnmarshalRejectsUnknownNestedField(t *testing.T) {
	t.Parallel()

	type inner struct {
		Value string `json:"value"`
	}
	type outer struct {
		Inner inner `json:"inner"`
	}
	var result outer
	if err := StrictUnmarshal([]byte(`{"inner":{"value":"ok","extra":true}}`), &result); err == nil {
		t.Fatal("StrictUnmarshal unexpectedly accepted an unknown field")
	}
	if err := StrictUnmarshal([]byte(`{"inner":{"value":"ok"}}`), &result); err != nil {
		t.Fatal(err)
	}
	want := outer{Inner: inner{Value: "ok"}}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
}

func TestStrictUnmarshalRejectsCaseFoldedKnownField(t *testing.T) {
	t.Parallel()

	type document struct {
		EventID string `json:"event_id"`
	}
	var result document
	if err := StrictUnmarshal([]byte(`{"EVENT_ID":"event-1"}`), &result); err == nil {
		t.Fatal("StrictUnmarshal unexpectedly accepted a case-folded field name")
	}
	if err := StrictUnmarshal([]byte(`{"event_id":"event-1"}`), &result); err != nil {
		t.Fatal(err)
	}
}

func TestStrictUnmarshalRejectsMissingZeroAndNullableFields(t *testing.T) {
	t.Parallel()

	type document struct {
		Enabled bool    `json:"enabled"`
		Reason  *string `json:"reason"`
	}
	for name, input := range map[string]string{
		"missing bool":     `{"reason":null}`,
		"missing nullable": `{"enabled":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			var result document
			if err := StrictUnmarshal([]byte(input), &result); err == nil {
				t.Fatalf("StrictUnmarshal unexpectedly accepted %s", input)
			}
		})
	}
	var result document
	if err := StrictUnmarshal([]byte(`{"enabled":false,"reason":null}`), &result); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizeEnforcesNestingLimit(t *testing.T) {
	t.Parallel()

	atLimit := strings.Repeat("[", maxNestingDepth) + "null" + strings.Repeat("]", maxNestingDepth)
	if _, err := Canonicalize([]byte(atLimit)); err != nil {
		t.Fatalf("Canonicalize rejected JSON at the nesting limit: %v", err)
	}

	tooDeep := "[" + atLimit + "]"
	if _, err := Canonicalize([]byte(tooDeep)); err == nil {
		t.Fatal("Canonicalize unexpectedly accepted JSON beyond the nesting limit")
	}
}

func TestStrictUnmarshalKeepsMapsAndRawMessagesOpaque(t *testing.T) {
	t.Parallel()

	type document struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
		Payload  json.RawMessage            `json:"payload"`
	}
	input := []byte(`{"metadata":{"Arbitrary-Key":{"CASE_FOLDED":true}},"payload":{"Unstructured":1}}`)
	var result document
	if err := StrictUnmarshal(input, &result); err != nil {
		t.Fatal(err)
	}
	if string(result.Metadata["Arbitrary-Key"]) != `{"CASE_FOLDED":true}` {
		t.Fatalf("metadata raw message = %s", result.Metadata["Arbitrary-Key"])
	}
	if string(result.Payload) != `{"Unstructured":1}` {
		t.Fatalf("payload raw message = %s", result.Payload)
	}
}

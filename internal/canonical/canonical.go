// Package canonical implements the deliberately small canonical JSON profile
// used by eventctl's signed protocol objects.
//
// The profile accepts JSON nulls, booleans, strings, arrays, objects, and
// arbitrary-size base-10 integers. Object keys are ordered by their UTF-8 byte
// representation. Duplicate keys, non-integer numbers, invalid UTF-8, and lone
// UTF-16 surrogate escapes are rejected. Protocol structures use strings for
// identifiers, so signed values do not depend on another implementation's
// floating-point or integer width.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxNestingDepth = 64

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// Marshal encodes v using eventctl's canonical JSON profile.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}
	return Canonicalize(raw)
}

// Canonicalize validates raw as one JSON value and returns its canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	value, err := decodeValue(raw)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	if err := writeValue(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func decodeValue(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validateSurrogateEscapes(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON contains a trailing value")
		}
		return nil, fmt.Errorf("read trailing JSON: %w", err)
	}

	return value, nil
}

// StrictUnmarshal rejects duplicate keys, non-canonical value types, trailing
// data, and missing, unknown, or case-folded struct fields before decoding raw
// into dst. Protocol structs deliberately do not use omitempty: nullable fields
// must still be present as JSON null.
func StrictUnmarshal(raw []byte, dst any) error {
	if dst == nil {
		return errors.New("decode destination is nil")
	}
	value, err := decodeValue(raw)
	if err != nil {
		return err
	}
	if err := validateExactFields(value, reflect.TypeOf(dst), "$"); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return fmt.Errorf("read trailing JSON: %w", err)
	}
	return nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode JSON token: %w", err)
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if number, ok := token.(json.Number); ok {
			return parseInteger(number)
		}
		return token, nil
	}
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("JSON nesting depth exceeds %d", maxNestingDepth)
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, fmt.Errorf("decode object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("close object: %w", err)
		}
		if end != json.Delim('}') {
			return nil, errors.New("object is not closed")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("close array: %w", err)
		}
		if end != json.Delim(']') {
			return nil, errors.New("array is not closed")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

type jsonFieldCandidate struct {
	typeOf reflect.Type
	depth  int
	tagged bool
}

// validateExactFields prevents encoding/json's case-insensitive field matching
// from widening signed protocol schemas. Maps intentionally accept arbitrary
// keys, and types with custom JSON decoding (including json.RawMessage) remain
// opaque so callers can explicitly opt into carrying unstructured JSON.
func validateExactFields(value any, destination reflect.Type, path string) error {
	for destination.Kind() == reflect.Pointer {
		if destination.Implements(jsonUnmarshalerType) {
			return nil
		}
		destination = destination.Elem()
	}
	if implementsJSONUnmarshaler(destination) || value == nil {
		return nil
	}

	switch destination.Kind() {
	case reflect.Interface:
		return nil
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := exactJSONFields(destination)
		for name, item := range object {
			fieldType, exists := fields[name]
			if !exists {
				return fmt.Errorf("unknown JSON field %q at %s", name, path)
			}
			if err := validateExactFields(item, fieldType, path+"."+name); err != nil {
				return err
			}
		}
		for name := range fields {
			if _, exists := object[name]; !exists {
				return fmt.Errorf("missing required JSON field %q at %s", name, path)
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for name, item := range object {
			if err := validateExactFields(item, destination.Elem(), path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return nil
		}
		for index, item := range array {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			if err := validateExactFields(item, destination.Elem(), itemPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func implementsJSONUnmarshaler(typeOf reflect.Type) bool {
	if typeOf.Implements(jsonUnmarshalerType) {
		return true
	}
	return typeOf.Kind() != reflect.Pointer && reflect.PointerTo(typeOf).Implements(jsonUnmarshalerType)
}

func exactJSONFields(typeOf reflect.Type) map[string]reflect.Type {
	candidates := make(map[string][]jsonFieldCandidate)
	collectJSONFields(typeOf, 0, make(map[reflect.Type]bool), candidates)

	fields := make(map[string]reflect.Type, len(candidates))
	for name, possible := range candidates {
		minimumDepth := possible[0].depth
		for _, candidate := range possible[1:] {
			if candidate.depth < minimumDepth {
				minimumDepth = candidate.depth
			}
		}

		var dominant []jsonFieldCandidate
		for _, candidate := range possible {
			if candidate.depth == minimumDepth {
				dominant = append(dominant, candidate)
			}
		}
		if len(dominant) == 1 {
			fields[name] = dominant[0].typeOf
			continue
		}

		var tagged []jsonFieldCandidate
		for _, candidate := range dominant {
			if candidate.tagged {
				tagged = append(tagged, candidate)
			}
		}
		if len(tagged) == 1 {
			fields[name] = tagged[0].typeOf
		}
	}
	return fields
}

func collectJSONFields(
	typeOf reflect.Type,
	depth int,
	ancestors map[reflect.Type]bool,
	candidates map[string][]jsonFieldCandidate,
) {
	for typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	if typeOf.Kind() != reflect.Struct || ancestors[typeOf] {
		return
	}
	ancestors[typeOf] = true
	defer delete(ancestors, typeOf)

	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		tagged := name != ""

		promotedType := field.Type
		for promotedType.Kind() == reflect.Pointer {
			promotedType = promotedType.Elem()
		}
		if field.Anonymous && !tagged && promotedType.Kind() == reflect.Struct {
			collectJSONFields(promotedType, depth+1, ancestors, candidates)
			continue
		}
		if !field.IsExported() {
			continue
		}
		if !tagged {
			name = field.Name
		}
		candidates[name] = append(candidates[name], jsonFieldCandidate{
			typeOf: field.Type,
			depth:  depth,
			tagged: tagged,
		})
	}
}

func parseInteger(number json.Number) (*big.Int, error) {
	text := number.String()
	if text == "" {
		return nil, errors.New("empty JSON number")
	}
	start := 0
	if text[0] == '-' {
		start = 1
	}
	if start == len(text) {
		return nil, fmt.Errorf("invalid integer %q", text)
	}
	if text[start] == '0' && len(text)-start != 1 {
		return nil, fmt.Errorf("integer %q has a leading zero", text)
	}
	for _, character := range text[start:] {
		if character < '0' || character > '9' {
			return nil, fmt.Errorf("non-integer JSON number %q is not allowed", text)
		}
	}
	integer, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer %q", text)
	}
	return integer, nil
}

func writeValue(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Errorf("encode string: %w", err)
		}
		output.Write(encoded)
	case *big.Int:
		output.WriteString(typed.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeValue(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return fmt.Errorf("encode object key: %w", err)
			}
			output.Write(encodedKey)
			output.WriteByte(':')
			if err := writeValue(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
	return nil
}

func validateSurrogateEscapes(raw []byte) error {
	insideString := false
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if !insideString {
			if character == '"' {
				insideString = true
			}
			continue
		}
		if character == '"' {
			insideString = false
			continue
		}
		if character != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return errors.New("unterminated string escape")
		}
		if raw[index] != 'u' {
			continue
		}
		codeUnit, next, err := parseCodeUnit(raw, index)
		if err != nil {
			return err
		}
		index = next - 1
		if codeUnit >= 0xD800 && codeUnit <= 0xDBFF {
			if next+1 >= len(raw) || raw[next] != '\\' || raw[next+1] != 'u' {
				return errors.New("high surrogate is not followed by a low surrogate")
			}
			low, afterLow, err := parseCodeUnit(raw, next+1)
			if err != nil {
				return err
			}
			if low < 0xDC00 || low > 0xDFFF || !utf16.IsSurrogate(rune(low)) {
				return errors.New("high surrogate is not followed by a low surrogate")
			}
			index = afterLow - 1
			continue
		}
		if codeUnit >= 0xDC00 && codeUnit <= 0xDFFF {
			return errors.New("low surrogate is not preceded by a high surrogate")
		}
	}
	return nil
}

func parseCodeUnit(raw []byte, uIndex int) (uint16, int, error) {
	if uIndex+5 > len(raw) {
		return 0, 0, errors.New("truncated Unicode escape")
	}
	hexDigits := string(raw[uIndex+1 : uIndex+5])
	parsed, err := strconv.ParseUint(hexDigits, 16, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid Unicode escape \\u%s", hexDigits)
	}
	return uint16(parsed), uIndex + 5, nil
}

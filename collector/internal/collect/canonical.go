package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Error string

func (e Error) Error() string { return string(e) }
func Code(err error) string {
	if e, ok := err.(Error); ok {
		return string(e)
	}
	return "IO_FAILURE"
}
func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, Error("JSON_ENCODING")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func strict(b []byte, v any) error {
	if !validEscapes(b) || uniqueJSON(b) != nil {
		return Error("INVALID_JSON_CONTRACT")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return Error("INVALID_JSON_CONTRACT")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Error("INVALID_JSON_CONTRACT")
	}
	return nil
}

// encoding/json alone accepts duplicate keys and malformed Unicode replacement.
// Contracts and checksummed states must have a single unambiguous interpretation.
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes := 0
	var read func(int) error
	read = func(depth int) error {
		nodes++
		if depth > 64 || nodes > 100000 {
			return Error("JSON_COMPLEXITY")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || keys[key] {
						return Error("DUPLICATE_JSON_KEY")
					}
					keys[key] = true
					if e = read(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = read(depth + 1); e != nil {
						return e
					}
				}
			default:
				return Error("INVALID_JSON_CONTRACT")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := read(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return Error("INVALID_JSON_CONTRACT")
	}
	return nil
}

// Reject malformed UTF-8 and surrogate escapes before encoding/json can replace
// them. Duplicate keys, deep values and ambiguous numeric representations are
// validated before constructing a bounded Python-compatible canonical payload.
func validEscapes(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		v, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
	}
	return true
}
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				b.WriteString(`\u`)
				b.WriteString("0000"[:4-len(strconv.FormatInt(int64(r), 16))])
				b.WriteString(strconv.FormatInt(int64(r), 16))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func number(s string) (string, error) {
	if len(s) > 128 {
		return "", Error("NUMBER_LIMIT")
	}
	if !strings.ContainsAny(s, ".eE") {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return "", Error("INVALID_NUMBER")
		}
		return n.Text(10), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", Error("INVALID_NUMBER")
	}
	exp := strconv.FormatFloat(f, 'e', -1, 64)
	parts := strings.Split(exp, "e")
	power, _ := strconv.Atoi(parts[1])
	if power < -4 || power >= 16 {
		return exp, nil
	}
	out := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(out, ".") {
		out += ".0"
	}
	return out, nil
}
func canonical(v any) (string, error) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			s, e := canonical(x[k])
			if e != nil {
				return "", e
			}
			out = append(out, quote(k)+":"+s)
		}
		return "{" + strings.Join(out, ",") + "}", nil
	case []any:
		out := make([]string, 0, len(x))
		for _, v := range x {
			s, e := canonical(v)
			if e != nil {
				return "", e
			}
			out = append(out, s)
		}
		return "[" + strings.Join(out, ",") + "]", nil
	case string:
		return quote(x), nil
	case json.Number:
		return number(string(x))
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case nil:
		return "null", nil
	}
	return "", Error("UNSUPPORTED_JSON")
}
func payload(b []byte) (map[string]any, []byte, error) {
	if !validEscapes(b) {
		return nil, nil, Error("INVALID_ENCODING")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > 24 || nodes > 10000 {
			return nil, Error("PAYLOAD_COMPLEXITY")
		}
		t, e := d.Token()
		if e != nil {
			return nil, Error("MALFORMED_JSON")
		}
		switch v := t.(type) {
		case json.Delim:
			if v == '{' {
				m := map[string]any{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return nil, Error("MALFORMED_JSON")
					}
					k, ok := key.(string)
					if !ok {
						return nil, Error("MALFORMED_JSON")
					}
					for _, r := range k {
						if r < 32 {
							return nil, Error("CONTROL_CHARACTER")
						}
					}
					if _, yes := m[k]; yes {
						return nil, Error("DUPLICATE_JSON_KEY")
					}
					item, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[k] = item
				}
				if _, e = d.Token(); e != nil {
					return nil, Error("MALFORMED_JSON")
				}
				return m, nil
			}
			if v == '[' {
				a := []any{}
				for d.More() {
					item, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, item)
				}
				if _, e = d.Token(); e != nil {
					return nil, Error("MALFORMED_JSON")
				}
				return a, nil
			}
			return nil, Error("MALFORMED_JSON")
		case string:
			for _, r := range v {
				if r < 32 {
					return nil, Error("CONTROL_CHARACTER")
				}
			}
			return v, nil
		default:
			return v, nil
		}
	}
	v, e := read(0)
	if e != nil {
		return nil, nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, nil, Error("MALFORMED_JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, Error("OBJECT_REQUIRED")
	}
	s, e := canonical(m)
	return m, []byte(s), e
}

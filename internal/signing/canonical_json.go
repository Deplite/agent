package signing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON encodes value using the deterministic, key-sorted form
// used by the Deplite backend: object keys are sorted lexicographically,
// no whitespace is emitted, and strings use Go's default JSON escaping
// (<, >, & and U+2028/U+2029 escaped to \uXXXX) so the bytes match the
// backend's canonicalJsonStringify output.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(w *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if x {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case json.Number:
		w.WriteString(x.String())
	case string:
		s, err := encodeString(x)
		if err != nil {
			return err
		}
		w.Write(s)
	case []any:
		w.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeCanonical(w, e); err != nil {
				return err
			}
		}
		w.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			ks, err := encodeString(k)
			if err != nil {
				return err
			}
			w.Write(ks)
			w.WriteByte(':')
			if err := writeCanonical(w, x[k]); err != nil {
				return err
			}
		}
		w.WriteByte('}')
	default:
		return fmt.Errorf("canonicaljson: unsupported type %T", v)
	}
	return nil
}

// encodeString emits a JSON string literal byte-identical to Go's
// encoding/json default (HTML-escaping) output, which the backend's
// canonicalJsonStringify now mirrors: <, >, ampersand and U+2028/U+2029
// escape to their \uXXXX forms. Presigned download URLs carry ampersands
// between query params, so escaping them is required to match the signed
// bytes.
func encodeString(s string) ([]byte, error) {
	return json.Marshal(s)
}

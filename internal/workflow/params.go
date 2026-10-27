package workflow

import (
	"fmt"
	"regexp"
	"strconv"
)

// ResolveParams validates supplied values against the workflow's
// declared params, applies defaults for missing values, and returns a
// new map with normalized (typed) values. Unknown supplied keys are
// rejected.
func (w Workflow) ResolveParams(supplied map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(w.Params))
	declared := make(map[string]Param, len(w.Params))
	for _, p := range w.Params {
		declared[p.Name] = p
	}
	for k := range supplied {
		if _, ok := declared[k]; !ok {
			return nil, fmt.Errorf("param %q: not declared", k)
		}
	}
	for _, p := range w.Params {
		v, present := supplied[p.Name]
		if !present {
			if p.Required {
				return nil, fmt.Errorf("param %q: required", p.Name)
			}
			if p.Default != nil {
				out[p.Name] = p.Default
			}
			continue
		}
		if err := checkParamValue(p, v); err != nil {
			return nil, fmt.Errorf("param %q: %w", p.Name, err)
		}
		out[p.Name] = coerceParamValue(p, v)
	}
	return out, nil
}

func checkParamValue(p Param, v any) error {
	switch p.Type {
	case ParamString, ParamEnum:
		s, ok := asString(v)
		if !ok {
			return fmt.Errorf("expected string, got %T", v)
		}
		if p.Type == ParamEnum {
			for _, opt := range p.Options {
				if s == opt {
					return nil
				}
			}
			return fmt.Errorf("value %q not in options %v", s, p.Options)
		}
		if p.Pattern != "" {
			re, err := regexp.Compile(p.Pattern)
			if err != nil {
				return fmt.Errorf("invalid pattern: %w", err)
			}
			if !re.MatchString(s) {
				return fmt.Errorf("value %q does not match pattern %q", s, p.Pattern)
			}
		}
		if p.Min != nil && float64(len(s)) < *p.Min {
			return fmt.Errorf("length %d < min %v", len(s), *p.Min)
		}
		if p.Max != nil && float64(len(s)) > *p.Max {
			return fmt.Errorf("length %d > max %v", len(s), *p.Max)
		}
	case ParamNumber:
		n, ok := asNumber(v)
		if !ok {
			return fmt.Errorf("expected number, got %T", v)
		}
		if p.Min != nil && n < *p.Min {
			return fmt.Errorf("value %v < min %v", n, *p.Min)
		}
		if p.Max != nil && n > *p.Max {
			return fmt.Errorf("value %v > max %v", n, *p.Max)
		}
	case ParamBoolean:
		if _, ok := asBool(v); !ok {
			return fmt.Errorf("expected boolean, got %T", v)
		}
	}
	return nil
}

func coerceParamValue(p Param, v any) any {
	switch p.Type {
	case ParamNumber:
		if n, ok := asNumber(v); ok {
			return n
		}
	case ParamBoolean:
		if b, ok := asBool(v); ok {
			return b
		}
	case ParamString, ParamEnum:
		if s, ok := asString(v); ok {
			return s
		}
	}
	return v
}

func asString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	default:
		return "", false
	}
}

func asNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case string:
		if n, err := strconv.ParseFloat(x, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func asBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	default:
		return false, false
	}
}

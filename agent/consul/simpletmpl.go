package consul

import (
	"bytes"
	"fmt"
	"strings"
)

// simpleInterpolateVars does extremely simple variable interpolation using
// "mustache" syntax of "a {{ b }} c" + {"b" : "xyz"} => "a xyz c"
func simpleInterpolateVars(s string, vars map[string]string) (string, error) {
	var buf bytes.Buffer
	err := walkSimpleTemplate(s, func(v string, isVar bool) error {
		if isVar {
			val, ok := vars[v]
			if !ok || val == "" {
				return fmt.Errorf("template %q is missing required variable %q", s, v)
			}
			buf.WriteString(val)
		} else {
			buf.WriteString(v)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// simpleCollectVars does a "dry run" of interpolateVars that checks for overall
// validation and then emits all of the var names found
func simpleCollectVars(s string) ([]string, error) {
	found := make(map[string]struct{})
	var ret []string

	err := walkSimpleTemplate(s, func(v string, isVar bool) error {
		if isVar {
			if _, ok := found[v]; !ok {
				ret = append(ret, v)
				found[v] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func walkSimpleTemplate(s string, f func(s string, isVar bool) error) error {
	const (
		varStart = "{{"
		varEnd   = "}}"
	)

	toks := simpleTokenize(s, varStart, varEnd)

	for i := 0; i < len(toks); {
		tok := toks[i]

		if tok == varEnd {
			return fmt.Errorf("template is invalid: %q", s)
		} else if tok == varStart {
			if i+2 >= len(toks) {
				return fmt.Errorf("template is invalid: %q", s)
			} else if toks[i+1] == varStart || toks[i+1] == varEnd || toks[i+2] != varEnd {
				return fmt.Errorf("template is invalid: %q", s)
			}
			varname := strings.TrimSpace(toks[i+1])
			if varname == "" {
				return fmt.Errorf("template is invalid: %q", s)
			}

			if err := f(varname, true); err != nil {
				return err
			}
			i += 3
		} else {
			if err := f(tok, false); err != nil {
				return err
			}
			i++
		}
	}
	return nil
}

func simpleTokenize(s, sep0, sep1 string) []string {
	if s == "" {
		return nil
	}

	n0 := strings.Count(s, sep0)
	n1 := strings.Count(s, sep1)
	n := n0 + n1

	if n == 0 {
		return []string{s}
	}

	a := make([]string, 0, 2*n+1)
	for {
		m0 := strings.Index(s, sep0)
		m1 := strings.Index(s, sep1)

		var (
			m   int
			sep string
		)
		if m0 == -1 && m1 == -1 {
			break
		}
		if m1 == -1 || (m0 != -1 && m0 < m1) {
			m = m0
			sep = sep0
		} else {
			m = m1
			sep = sep1
		}

		if s[:m] != "" {
			a = append(a, s[:m])
		}
		a = append(a, sep)
		s = s[m+len(sep):]
	}

	if s != "" {
		a = append(a, s)
	}
	return a
}

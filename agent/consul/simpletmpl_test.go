package consul

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimpleInterpolateVars_ok(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
		vars string
		exp  string
	}{
		{"empty", "", "", ""},
		{"no vars", "nothing", "", "nothing"},
		{"just var", "{{ item }}", "item=value", "value"},
		{"var in middle", "before {{ item }}after", "item=value", "before valueafter"},
		{"two vars", "before {{ item }}after {{ more }}", "item=value,more=xyz", "before valueafter xyz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			vars := mapifyKVList(t, test.vars)
			out, err := simpleInterpolateVars(test.in, vars)
			require.NoError(t, err)
			require.Equal(t, test.exp, out)
		})
	}
}
func TestSimpleInterpolateVars_bad(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
		vars string
	}{
		{"just start", "{{", ""},
		{"just end", "}}", ""},
		{"backwards", "}}{{", ""},
		{"no varname", "{{}}", ""},
		{"missing map key", "{{item}}", ""},
		{"missing map val", "{{item}}", "item="},
		{"var without start", " item }}", "item=value"},
		{"var without end", "{{ item ", "item=value"},
		{"two vars missing second start", "before {{ item }}after  more }}", "item=value,more=xyz"},
		{"two vars missing first end", "before {{ item after {{ more }}", "item=value,more=xyz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			vars := mapifyKVList(t, test.vars)
			out, err := simpleInterpolateVars(test.in, vars)
			require.NotNil(t, err)
			require.Equal(t, out, "")
		})
	}
}

func TestSimpleCollectVars_ok(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
		exp  []string
	}{
		{"empty", "", []string{}},
		{"no vars", "nothing", []string{}},
		{"just var", "{{ item }}", []string{"item"}},
		{"var in middle", "before {{ item }}after", []string{"item"}},
		{"two vars", "before {{ item }}after {{ more }}", []string{"item", "more"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := simpleCollectVars(test.in)
			require.NoError(t, err)
			require.ElementsMatch(t, test.exp, out)
		})
	}
}

func TestSimpleCollectVars_bad(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
	}{
		{"just start", "{{"},
		{"just end", "}}"},
		{"backwards", "}}{{"},
		{"no varname", "{{}}"},
		{"var without start", " item }}"},
		{"var without end", "{{ item "},
		{"two vars missing second start", "before {{ item }}after  more }}"},
		{"two vars missing first end", "before {{ item after {{ more }}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := simpleCollectVars(test.in)
			require.NotNil(t, err)
		})
	}
}

func mapifyKVList(t *testing.T, kvs string) map[string]string {
	m := make(map[string]string)
	if kvs == "" {
		return m
	}

	parts := strings.Split(kvs, ",")

	for _, kv := range parts {
		kv = strings.TrimSpace(kv)
		parts := strings.Split(kv, "=")
		require.Len(t, parts, 2, kv)
		m[parts[0]] = parts[1]
	}
	return m
}

func TestSimpleTokenize(t *testing.T) {
	for _, test := range []struct {
		in  string
		exp []string
	}{
		{"", []string{}},
		{"nothing", []string{"nothing"}},
		{"{{", []string{"{{"}},
		{"}}", []string{"}}"}},
		{"{{}}", []string{"{{", "}}"}},
		{"a{{b}}c", []string{"a", "{{", "b", "}}", "c"}},
		{"{{b}}c", []string{"{{", "b", "}}", "c"}},
		{"a{{}}c", []string{"a", "{{", "}}", "c"}},
		{"a{{b}}", []string{"a", "{{", "b", "}}"}},
		{"a {{ b }} c", []string{"a ", "{{", " b ", "}}", " c"}},
	} {
		t.Run(test.in, func(t *testing.T) {
			out := simpleTokenize(test.in, "{{", "}}")
			require.ElementsMatch(t, test.exp, out, "got: %#v", out)
		})
	}
}

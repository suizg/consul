package consul

import (
	"strings"
	"testing"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/stretchr/testify/require"
)

func TestDoesRoleBindingRuleMatch(t *testing.T) {
	makeF := func(s string) map[string]string {
		kvs := strings.Split(s, " ")
		out := make(map[string]string)
		for _, kv := range kvs {
			k, v, ok := parseExactMatchSelector(kv) // cheat and reuse this function
			require.True(t, ok)
			out[k] = v
		}
		return out
	}

	for _, test := range []struct {
		name   string
		match1 []string
		match2 []string // TODO use this
		fields map[string]string
		ok     bool
	}{
		{"no fields",
			[]string{"a=b"}, nil, nil, false},
		{"1 term ok",
			[]string{"a=b"}, nil, makeF("a=b"), true},
		{"1 term no field",
			[]string{"a=b"}, nil, makeF("c=d"), false},
		{"1 term wrong value",
			[]string{"a=b"}, nil, makeF("a=z"), false},
		{"2 terms ok",
			[]string{"a=b", "c=d"}, nil, makeF("a=b c=d"), true},
		{"2 terms one missing field",
			[]string{"a=b", "c=d"}, nil, makeF("a=b"), false},
		{"2 terms one wrong value",
			[]string{"a=b", "c=d"}, nil, makeF("a=z c=d"), false},
		///////////////////////////////
		{"no fields (no selectors)",
			nil, nil, nil, true},
		{"1 term ok (no selectors)",
			nil, nil, makeF("a=b"), true},
	} {
		var rule structs.ACLRoleBindingRule
		if len(test.match1) > 0 {
			rule.Match = append(rule.Match, &structs.ACLRoleBindingRuleMatch{
				Selector: test.match1,
			})
		}
		if len(test.match2) > 0 {
			rule.Match = append(rule.Match, &structs.ACLRoleBindingRuleMatch{
				Selector: test.match2,
			})
		}

		t.Run(test.name, func(t *testing.T) {
			ok := doesRoleBindingRuleMatch(&rule, test.fields)
			require.Equal(t, test.ok, ok)
		})
	}
}

func TestParseExactMatchSelector(t *testing.T) {
	for _, test := range []struct {
		input    string
		lhs, rhs string
		ok       bool
	}{
		{"", "", "", false},
		{"=", "", "", false},
		{" =", "", "", false},
		{"= ", "", "", false},
		{" = ", "", "", false},
		{"a=", "", "", false},
		{"a= ", "", "", false},
		{"=b", "", "", false},
		{" =b", "", "", false},
		{"a=b", "a", "b", true},
		{" a = b ", "a", "b", true},
		{"a=b=", "", "", false},
		{"=a=b", "", "", false},
		{"a==b", "", "", false},
	} {
		t.Run(test.input, func(t *testing.T) {
			lhs, rhs, ok := parseExactMatchSelector(test.input)
			require.Equal(t, test.ok, ok)
			require.Equal(t, test.lhs, lhs)
			require.Equal(t, test.rhs, rhs)
		})
	}
}

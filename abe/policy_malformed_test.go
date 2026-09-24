package abe_test

import (
	"testing"

	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
)

// BooleanToMSP splits expressions at gate words and processes the halves. Any
// leading or doubled gate, empty slice, etc. produced an empty operand
// somewhere in the recursion which would create 'ghost' leftovers which may
// yield surprising behavior, or 'invisible' attributes that validate

func TestBooleanToMSP_ErrorsOnMalformedExpressions(t *testing.T) {
	cases := map[string]string{
		"leading gate, empty left operand":  "AND B",
		"doubled gate":                      "A AND AND B",
		"empty policy string":               "",
		"trailing AND, empty right operand": "A AND",
		"trailing OR, empty right operand":  "A OR",
	}
	for name, expr := range cases {
		expr := expr
		t.Run(name, func(t *testing.T) {
			var err error
			assert.NotPanics(t, func() {
				_, err = abe.BooleanToMSP(expr, false)
			}, "BooleanToMSP(%q, ...) should not panic", expr)
			assert.Error(
				t,
				err,
				"BooleanToMSP(%q, ...) should return an error for an empty operand",
				expr,
			)
		})
	}
}

func TestBooleanToMSP_UnbalancedParensReturnCleanError(t *testing.T) {
	cases := map[string]string{
		"missing closing paren": "(A AND B",
		"missing opening paren": "A AND B)",
	}
	for name, expr := range cases {
		expr := expr
		t.Run(name, func(t *testing.T) {
			_, err := abe.BooleanToMSP(expr, false)
			if assert.Error(t, err, "BooleanToMSP(%q, ...) should return an error", expr) {
				assert.Contains(
					t,
					err.Error(),
					"bad boolean expression or attributes contain ( or )",
				)
			}
		})
	}
}

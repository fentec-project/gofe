package abe_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/fentec-project/gofe/abe"
)

func andChainPolicy(n int) string {
	attrs := make([]string, n)
	for i := range attrs {
		attrs[i] = "attr" + strconv.Itoa(i)
	}
	return strings.Join(attrs, " AND ")
}

func BenchmarkFAMEEncrypt(b *testing.B) {
	a := abe.NewFAME()
	pk, _, err := a.GenerateMasterKeys()
	if err != nil {
		b.Fatalf("failed to generate master keys: %v", err)
	}

	for _, n := range []int{8, 32, 128} {
		msp, err := abe.BooleanToMSP(andChainPolicy(n), false)
		if err != nil {
			b.Fatalf("failed to build MSP (n=%d): %v", n, err)
		}

		b.Run(fmt.Sprintf("AND-n%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := a.Encrypt("Functional encryption library in Go", msp, pk); err != nil {
					b.Fatalf("encrypt failed: %v", err)
				}
			}
		})
	}
}

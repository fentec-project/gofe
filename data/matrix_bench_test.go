package data

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/sample"
)

func BenchmarkGuassianEliminationSolver(b *testing.B) {
	p := big.NewInt(7919) // large prime
	sampler := sample.NewUniform(p)

	for _, n := range []int{64, 256, 512} {
		mat, err := NewRandomMatrix(n, n, sampler)
		if err != nil {
			b.Fatalf("failed to build matrix for n=%d: %v", n, err)
		}
		x, err := NewRandomVector(n, sampler)
		if err != nil {
			b.Fatalf("failed to build vector for n=%d: %v", n, err)
		}
		v, err := mat.MulVec(x)
		if err != nil {
			b.Fatalf("failed to build target vector for n=%d: %v", n, err)
		}
		v = v.Mod(p)

		b.Run(fmt.Sprintf("n%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := GaussianEliminationSolver(mat, v, p); err != nil {
					b.Fatalf("solve failed: %v", err)
				}
			}
		})
	}
}

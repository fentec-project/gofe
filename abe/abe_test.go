package abe

import (
	"testing"
	"fmt"
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
)

func TestAbe(t *testing.T) {
	a := newAbe(10)
	fmt.Println(a)
}

func TestGaussianElimintaion(t *testing.T) {
	p := big.NewInt(5)
	sampler := sample.NewUniform(p)
	mat, err := data.NewRandomMatrix(3, 3, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}
	v, err := data.NewRandomVector(3, sampler)
	fmt.Println(mat, v)
	x, err := gaussianElimination(mat, v, p)
	fmt.Println(x)
	vCheck, err := mat.MulVec(x)
	vCheck = vCheck.Mod(p)
	//assert.Equal(t, v, vCheck)
	fmt.Println(v, vCheck)
}

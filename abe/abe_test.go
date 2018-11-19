package abe

import (
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
	"fmt"
)

func TestAbe(t *testing.T) {
	l := 10
	a := newAbe(l)
	pubKey, sk, err := a.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to genrate master keys: %v", err)
	}
	sampler := sample.NewUniform(a.Params.p)
	exponent, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to generate random values: %v", err)
	}
	gamma := []int{1, 2, 3}
	msg := new(bn256.GT).ScalarBaseMult(exponent)
	cipher, err := a.Encrypt(msg, gamma, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	//ones := make(data.Vector, 3)
	//for i := 0; i < len(ones); i++ {
	//	ones[i] = big.NewInt(1)
	//}
	//var mat data.Matrix
	//for {
	//	mat, err = data.NewRandomMatrix(3, 3, sampler)
	//	_, err := gaussianElimination(mat, ones, a.Params.p)
	//	if err == nil {
	//		break
	//	}
	//}
	//
	//msp := &Msp{mat: mat, rowToAttrib: []int{1, 2, 3}}
	msp, err := BooleanToMsp("(1 OR 2) AND (2 OR 3)", a.Params.p)
	fmt.Println(msp.mat)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	keys, err := a.KeyGen(msp, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	emptyMsp := &Msp{mat: make(data.Matrix, 0), rowToAttrib: make([]int, 0)}
	_, err = a.KeyGen(emptyMsp, sk)
	assert.Error(t, err)

	abeKey := a.DelagateKeys(keys, msp, gamma)

	msgCheck, err := a.Decrypt(cipher, abeKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	assert.Equal(t, msg, msgCheck)
}

func TestBooleanToMsp(t *testing.T) {
	// create as msp struct out of a boolean expression
	p := big.NewInt(7)
	msp, err := BooleanToMsp("1 AND (((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", p)
	if err != nil {
		t.Fatalf("Error while processing a boolean expression: %v", err)
	}
	fmt.Println(msp.mat)

	// check if having attributes 1, 7 and 9 satisfies the expression, i.e. entries 0, 2, 4
	// of a msp matrix span vector [1, 0,..., 0]
	v := make(data.Vector, len(msp.mat[0]))
	for i := 0; i < len(v); i++ {
		v[i] = big.NewInt(1)
	}
	m := make(data.Matrix, 3)
	m[0] = msp.mat[0]
	m[1] = msp.mat[2]
	m[2] = msp.mat[4]

	x, err := gaussianElimination(m.Transpose(), v, p)
	if err != nil {
		t.Fatalf("Error finding a vector: %v", err)
	}
	assert.NotNil(t, x)

	// check if an error is generated if the boolean expression is not correct
	_, err = BooleanToMsp("1 AND ((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", p)
	assert.Error(t, err)

}

func TestGaussianElimintaion(t *testing.T) {
	p := big.NewInt(17)
	sampler := sample.NewUniform(p)
	mat, err := data.NewRandomMatrix(100, 50, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}
	xCheck, err := data.NewRandomVector(50, sampler)
	if err != nil {
		t.Fatalf("Error during vector generation: %v", err)
	}

	v, err := mat.MulVec(xCheck)
	v = v.Mod(p)
	x, err := gaussianElimination(mat, v, p)
	vCheck, err := mat.MulVec(x)
	vCheck = vCheck.Mod(p)
	assert.Equal(t, v, vCheck)

	vWrong, err := data.NewRandomVector(101, sampler)
	if err != nil {
		t.Fatalf("Error during vector generation: %v", err)
	}
	_, err = gaussianElimination(mat, vWrong, p)
	assert.Error(t, err)

	matWrong := make(data.Matrix, 0)
	_, err = gaussianElimination(matWrong, v, p)
	assert.Error(t, err)
}

package abe

import (
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
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

	ones := make(data.Vector, 3)
	for i := 0; i < len(ones); i++ {
		ones[i] = big.NewInt(1)
	}
	var mat data.Matrix
	for {
		mat, err = data.NewRandomMatrix(3, 3, sampler)
		_, err := gaussianElimination(mat, ones, a.Params.p)
		if err == nil {
			break
		}
	}

	msp := Msp{mat: mat, rowToAttrib: []int{1, 2, 3}}

	keys, err := a.KeyGen(msp, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	emptyMsp := Msp{mat: make(data.Matrix, 0), rowToAttrib: make([]int, 0)}
	_, err = a.KeyGen(emptyMsp, sk)
	assert.Error(t, err)

	abeKey := a.DelagateKeys(keys, msp, gamma)

	msgCheck, err := a.Decrypt(cipher, abeKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	assert.Equal(t, msg, msgCheck)
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

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
	// create a new ABE struct with the universe of l possible
	// attributes (attributes are denoted by the integers in [0, l)
	l := 10
	a := newAbe(l)

	// generate a a pubic and secret key for the scheme
	pubKey, sk, err := a.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to genrate master keys: %v", err)
	}

	// create a random message to be encrypted, for now
	// this is an element of an elliptic curve
	sampler := sample.NewUniform(a.Params.p)
	exponent, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to generate random values: %v", err)
	}
	msg := new(bn256.GT).ScalarBaseMult(exponent)

	// define a set of attributes (a subset of the universe of attributes)
	// that are needed for the encrypted message
	gamma := []int{0, 1, 2, 4}

	// encrypt the message
	cipher, err := a.Encrypt(msg, gamma, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// create a msp struct representing a policy of which attributes are needed
	// to decrypt the ciphertext
	msp, err := BooleanToMsp("(1 OR 4) AND (2 OR (0 AND 1))", a.Params.p)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v", err)
	}

	// generate keys for decryption, i.e. a vector of keys, for each row in
	// the msp matrix one ky
	keys, err := a.KeyGen(msp, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// test if error is returned when a bad Msp struct is given
	emptyMsp := &Msp{mat: make(data.Matrix, 0), rowToAttrib: make([]int, 0)}
	_, err = a.KeyGen(emptyMsp, sk)
	assert.Error(t, err)

	// produce a set of keys that are given to an entity with a set
	// of attributes in ownedAttrib
	ownedAttrib := []int{1, 2}
	abeKey := a.DelagateKeys(keys, msp, ownedAttrib)

	// decrypt the ciphertext with the set of delegated keys
	msgCheck, err := a.Decrypt(cipher, abeKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, msgCheck)

	// produce a set of keys that are given to an entity with a set
	// of insufficient attributes in ownedAttribInsuff
	ownedAttribInsuff := []int{4, 0}
	abeKeyInsuff := a.DelagateKeys(keys, msp, ownedAttribInsuff)

	// try to decrypt the ciphertext with the set of delegated keys
	msgCheck, err = a.Decrypt(cipher, abeKeyInsuff)
	assert.Error(t, err)
}

func TestBooleanToMsp(t *testing.T) {
	// create as msp struct out of a boolean expression
	p := big.NewInt(7)
	msp, err := BooleanToMsp("1 AND (((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", p)
	if err != nil {
		t.Fatalf("Error while processing a boolean expression: %v", err)
	}

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

	// check if an error is generated if the boolean expression is not in a correct form
	_, err = BooleanToMsp("1 AND ((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", p)
	assert.Error(t, err)

}

func TestGaussianElimintaion(t *testing.T) {
	// create instances mat, xTest and v for which mat * xTest = v
	// as a matrix vector multiplication over Z_p

	p := big.NewInt(17)
	sampler := sample.NewUniform(p)
	mat, err := data.NewRandomMatrix(100, 50, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	xTest, err := data.NewRandomVector(50, sampler)
	if err != nil {
		t.Fatalf("Error during vector generation: %v", err)
	}

	v, err := mat.MulVec(xTest)
	v = v.Mod(p)

	// test the Gaussian elimination algorithm that given v and mat
	// finds x such that mat * x = v
	x, err := gaussianElimination(mat, v, p)

	// test if the obtained x is correct
	vCheck, err := mat.MulVec(x)
	vCheck = vCheck.Mod(p)
	assert.Equal(t, v, vCheck)

	// test if errors are returned if the inputs have a wrong form
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

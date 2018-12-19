package abe_test

import (
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestFAME(t *testing.T) {
	// create a new ABE struct with the universe of attributes
	// denoted by integer
	a := abe.NewFAME()

	// generate a public key and a secret key for the scheme
	pubKey, sk, err := a.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to generate master keys: %v", err)
	}

	// create a random message to be encrypted, for now
	// this is an element of an elliptic curve
	sampler := sample.NewUniform(a.P)
	exponent, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to generate random values: %v", err)
	}
	msg := new(bn256.GT).ScalarBaseMult(exponent)

	// create a msp struct out of a boolean expression  representing the
	// policy specifying which attributes are needed to decrypt the ciphertext
	msp, err := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", a.P, false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v", err)
	}

	// encrypt the message msg with the decryption policy specified by the
	// msp structure
	cipher, err := a.Encrypt(msg, msp, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// define a set of attributes (a subset of the universe of attributes)
	// that an entity possesses
	gamma := []int{0, 2, 3, 5}

	// generate keys for decryption for an entity with
	// attributes gamma
	keys, err := a.GenerateAttribKeys(gamma, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// decrypt the ciphertext with the keys of an entity
	// that has sufficient attributes
	msgCheck, err := a.Decrypt(cipher, keys, pubKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, msgCheck)

	// define a set of attributes (a subset of the universe of attributes)
	// that an entity possesses
	gammaInsuff := []int{1, 3, 5}

	// generate keys for decryption for an entity with
	// attributes gammaInsuff
	keysInsuff, err := a.GenerateAttribKeys(gammaInsuff, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// try to decrypt the ciphertext with the keys of an entity
	// that has insufficient attributes
	_, err = a.Decrypt(cipher, keysInsuff, pubKey)
	assert.Error(t, err)
}

func TestHash(t *testing.T) {
	g1 := abe.HashG1("foo")
	g2 := abe.HashG1("bar")
	g3 := abe.HashG1("foo")
	assert.Equal(t, g1, g3)
	assert.NotEqual(t, g1, g2)
}
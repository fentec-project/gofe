/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package abe_test

import (
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestGSPW(t *testing.T) {
	// create a new ABE struct with the universe of l possible
	// attributes (attributes are denoted by the integers in [0, l)
	l := 10
	a := abe.NewGSPW(l)

	// generate a public key and a secret key for the scheme
	pubKey, sk, err := a.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to generate master keys: %v", err)
	}

	// create a random message to be encrypted, for now
	// this is an element of a pairing group G_T
	sampler := sample.NewUniform(a.Params.P)
	exponent, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to generate random values: %v", err)
	}
	msg := new(bn256.GT).ScalarBaseMult(exponent)

	// define a set of attributes (a subset of the universe of attributes)
	// that will later be used in the decryption policy of the message
	gamma := []int{0, 1, 2, 4}

	// encrypt the message
	cipher, err := a.Encrypt(msg, gamma, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// create a msp struct out of a boolean expression  representing the
	// policy specifying which attributes are needed to decrypt the ciphertext
	msp, err := abe.BooleanToMSP("(1 OR 4) AND (2 OR (0 AND 1))", true)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v", err)
	}

	// generate keys for decryption that correspond to provided msp struct,
	// i.e. a vector of keys, for each row in the msp matrix one key, having
	// the property that a subset of keys can decrypt a message iff the
	// corresponding rows span the vector of ones (which is equivalent to
	// corresponding attributes satisfy the boolean expression)
	keys, err := a.GeneratePolicyKeys(msp, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// test if error is returned when a bad Msp struct is given
	emptyMsp := &abe.MSP{Mat: make(data.Matrix, 0), RowToAttrib: make([]int, 0)}
	_, err = a.GeneratePolicyKeys(emptyMsp, sk)
	assert.Error(t, err)

	// produce a set of keys that are given to an entity with a set
	// of attributes in ownedAttrib
	ownedAttrib := []int{1, 2}
	abeKey := a.DelegateKeys(keys, msp, ownedAttrib)

	// decrypt the ciphertext with the set of delegated keys
	msgCheck, err := a.Decrypt(cipher, abeKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, msgCheck)

	// produce a set of keys that are given to an entity with a set
	// of insufficient attributes in ownedAttribInsuff
	ownedAttribInsuff := []int{4, 0}
	abeKeyInsuff := a.DelegateKeys(keys, msp, ownedAttribInsuff)

	// try to decrypt the ciphertext with the set of delegated keys
	msgCheck, err = a.Decrypt(cipher, abeKeyInsuff)
	assert.Error(t, err)
}

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

	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
)

func TestGPSW(t *testing.T) {
	// create a new GPSW struct with the universe of l possible
	// attributes (attributes are denoted by the integers in [0, l))
	l := 10
	a := abe.NewGPSW(l)

	// generate a public key and a secret key for the scheme
	pubKey, secKey, err := a.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to generate master keys: %v", err)
	}

	// create two messages to be encrypted
	msg1 := "Attack at dawn!"
	msg2 := "More chocolate!"

	// define a set of attributes (a subset of the universe of attributes)
	// that will be associated with the encryptions
	gamma1 := []int{0, 4, 5} // could be given also as []string{"0", "4", "5"}
	gamma2 := []int{0, 1, 4} // could be given also as []string{"0", "1", "4"}

	// encrypt the first message with associated attributes gamma1
	cipher1, err := a.Encrypt(msg1, gamma1, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// encrypt the second message with associated attributes gamma2
	cipher2, err := a.Encrypt(msg2, gamma2, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// create a msp struct out of a boolean expression representing the
	// policy specifying which attributes are needed to decrypt the ciphertext;
	// the boolean expression is a string of attributes joined by AND and OR
	// where attributes are integers from the interval [0, l)

	// note that the safety of the encryption is only proved if the mapping
	// msp.RowToAttrib from the rows of msp.Mat to attributes is injective, i.e.
	// only boolean expressions in which each attribute appears at most once
	// are allowed - if expressions with multiple appearances of an attribute
	// are needed, then this attribute can be split into more sub-attributes
	msp, err := abe.BooleanToMSP("(1 OR 4) AND (2 OR (0 AND 5))", true)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v", err)
	}

	// generate a key for decryption that correspond to provided msp struct,
	// i.e. a key that can decrypt a message iff the attributes associated
	// with the ciphertext satisfy the boolean expression
	abeKey, err := a.GeneratePolicyKey(msp, secKey)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// test if error is returned when a bad Msp struct is given
	emptyMsp := &abe.MSP{Mat: make(data.Matrix, 0), RowToAttrib: make([]string, 0)}
	_, err = a.GeneratePolicyKey(emptyMsp, secKey)
	assert.Error(t, err)

	// decrypt the first ciphertext with abeKey
	msgCheck, err := a.Decrypt(cipher1, abeKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg1, msgCheck)

	// try to decrypt the second ciphertext but fail with abeKey
	_, err = a.Decrypt(cipher2, abeKey)
	assert.Error(t, err)
}

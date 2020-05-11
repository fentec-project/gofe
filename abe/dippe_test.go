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

	"math/big"

	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
)

func TestDIPPE(t *testing.T) {
	// create a new DIPPE struct, choosing the security parameter
	d, err := abe.NewDIPPE(3)
	if err != nil {
		t.Fatalf("Failed to generate a new scheme: %v", err)
	}
	vecLen := 5

	// create authorities and their public keys
	auth := make([]*abe.DIPPEAuth, vecLen)
	pubKeys := make([]*abe.DIPPEPubKey, vecLen)
	for i := range auth {
		auth[i], err = d.NewDIPPEAuth(i)
		if err != nil {
			t.Fatalf("Failed to generate a new authority: %v", err)
		}
		pubKeys[i] = &auth[i].Pk
	}

	msg := "some message"

	// choose a policy vector
	policyVec := data.Vector([]*big.Int{big.NewInt(1), big.NewInt(-1),
		big.NewInt(1), big.NewInt(0), big.NewInt(0)})

	// encrypt the message with the chosen policy give by a policy vector,
	cipher, err := d.Encrypt(msg, policyVec, pubKeys)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// choose a unique user's GID
	userGID := "someGID"
	// choose user's vector, decryption is possible if and only if
	// the users's and policy vector are orthogonal
	userVec := data.Vector([]*big.Int{big.NewInt(0), big.NewInt(1),
		big.NewInt(1), big.NewInt(-3), big.NewInt(4)})

	// authorities generate decryption keys for the user
	userKeys := make([]data.VectorG2, vecLen)
	for i := range auth {
		userKeys[i], err = auth[i].DeriveKeyShare(userVec, pubKeys, userGID)
		if err != nil {
			t.Fatalf("Failed to generate a user key: %v", err)
		}
	}

	// user decrypts using collected keys
	dec, err := d.Decrypt(cipher, userKeys, userVec, userGID)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, dec)
}

func TestDIPPE_ABE_threshold(t *testing.T) {
	// this test transforms DIPPE scheme into an ABE scheme
	// with the exact threshold policy; in threshold policy each user has
	// attributes but only the users that have exactly the
	// threshold value of specified attributes can decrypt

	// create a new DIPPE struct, choosing the security parameter
	d, err := abe.NewDIPPE(3)
	if err != nil {
		t.Fatalf("Failed to generate a new scheme: %v", err)
	}
	// specify the number of all attributes
	numAttrib := 10

	// create authorities and their public keys
	auth := make([]*abe.DIPPEAuth, numAttrib+1)
	pubKeys := make([]*abe.DIPPEPubKey, numAttrib+1)
	for i := range auth {
		auth[i], err = d.NewDIPPEAuth(i)
		if err != nil {
			t.Fatalf("Failed to generate a new authority: %v", err)
		}
		pubKeys[i] = &auth[i].Pk
	}

	msg := "some important message"

	// choose attributes needed for the exact threshold policy and the
	// threshold value
	thresholdAttrib := []int{0, 2, 5, 8, 9}
	exactThreshold := 3
	// generate the exact threshold vector (this conversion allows the
	// DIPPE scheme to be used as an ABE threshold scheme)
	thresholdPolicyVec, err := d.ExactThresholdPolicyVecInit(thresholdAttrib, exactThreshold, numAttrib)
	if err != nil {
		t.Fatalf("Failed to generate threshold vector: %v", err)
	}

	// encrypt the message with the chosen threshold policy
	thresholdCipher, err := d.Encrypt(msg, thresholdPolicyVec, pubKeys)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// choose a unique user's GID
	thresholdUserGID := "thresholdGID"

	// choose the attributes possessed by the users
	thresholdUserAttrib := []int{0, 1, 5, 7, 9}

	// generate user's vector
	thresholdUserVec, err := d.AttributeVecInit(thresholdUserAttrib, numAttrib)
	if err != nil {
		t.Fatalf("Failed to generate attributes vector: %v", err)
	}

	// authorities generate decryption keys for the user
	thresholdUserKeys := make([]data.VectorG2, len(auth))
	for i := range auth {
		thresholdUserKeys[i], err = auth[i].DeriveKeyShare(thresholdUserVec, pubKeys, thresholdUserGID)
		if err != nil {
			t.Fatalf("Failed to generate a user key: %v", err)
		}
	}

	// user decrypts using collected keys
	dec, err := d.Decrypt(thresholdCipher, thresholdUserKeys, thresholdUserVec, thresholdUserGID)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, dec)
}

func TestDIPPE_ABE_conjugation(t *testing.T) {
	// this test transforms DIPPE scheme into an ABE scheme
	// with the conjugation policy; in the conjugation policy
	// the user must have all the specified attributes to be
	// able to decrypt

	// create a new DIPPE struct, choosing the security parameter
	d, err := abe.NewDIPPE(3)
	if err != nil {
		t.Fatalf("Failed to generate a new scheme: %v", err)
	}
	// specify the number of all attributes
	numAttrib := 10

	// create authorities and their public keys
	auth := make([]*abe.DIPPEAuth, numAttrib+1)
	pubKeys := make([]*abe.DIPPEPubKey, numAttrib+1)
	for i := range auth {
		auth[i], err = d.NewDIPPEAuth(i)
		if err != nil {
			t.Fatalf("Failed to generate a new authority: %v", err)
		}
		pubKeys[i] = &auth[i].Pk
	}

	msg := "some important message"

	// choose attributes needed for the conjunction policy
	conjunctAttrib := []int{1, 2, 3, 7}
	// generate the conjunction vector (this conversion allows the
	// DIPPE scheme to be used as an ABE conjunction scheme)
	conjunctPolicyVec, err := d.ConjunctionPolicyVecInit(conjunctAttrib, numAttrib)
	if err != nil {
		t.Fatalf("Failed to generate conjucnction vector: %v", err)
	}

	// encrypt the message with the chosen conjunction policy
	conjunctCipher, err := d.Encrypt(msg, conjunctPolicyVec, pubKeys)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// choose a unique user's GID
	conjunctUserGID := "conjunctionGID"

	// choose the attributes possessed by the user
	conjunctUserAttrib := []int{0, 1, 2, 3, 7, 9}

	// generate user's vector
	conjunctUserVec, err := d.AttributeVecInit(conjunctUserAttrib, numAttrib)
	if err != nil {
		t.Fatalf("Failed to generate attributes vector: %v", err)
	}

	// authorities generate decryption keys for the user
	conjunctUserKeys := make([]data.VectorG2, len(auth))
	for i := range auth {
		conjunctUserKeys[i], err = auth[i].DeriveKeyShare(conjunctUserVec, pubKeys, conjunctUserGID)
		if err != nil {
			t.Fatalf("Failed to generate a user key: %v", err)
		}
	}

	// user decrypts using collected keys
	dec, err := d.Decrypt(conjunctCipher, conjunctUserKeys, conjunctUserVec, conjunctUserGID)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, dec)
}

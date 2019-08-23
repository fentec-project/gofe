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
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
	"math/big"
	"fmt"
	"github.com/fentec-project/gofe/sample"
)

func TestDIPPE(t *testing.T) {
	hashed := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	fmt.Println(hashed)

	twice := new(bn256.G2).Add(hashed, hashed)
	fmt.Println("tw", twice)



	//hashed = new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	//fmt.Println(hashed)

	twice = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	twice.Add(twice, hashed)
	twice.Add(twice, hashed)


	fmt.Println("tw", twice)

	hashed.Neg(hashed)
	twice = new(bn256.G2).Add(hashed, hashed)
	fmt.Println("neg", twice)

	twice = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	twice.Add(twice, hashed)
	twice.Add(twice, hashed)
	fmt.Println("neg", twice)


	// create a new FAME struct with the universe of attributes
	// denoted by integer
	d, err := abe.NewDIPPE(1)
	if err != nil {
		t.Fatalf("Failed to generate a new scheme: %v", err)
	}
	vecLen := 3

	// generate a public key and a secret key for the scheme
	auth := make([]*abe.DIPPEAuth, vecLen)
	pubKeys := make([]*abe.DIPPEPubKey, vecLen)
	for i := 0; i < vecLen; i++ {
		auth[i], err = d.NewDIPPEAuth(i)
		if err != nil {
			t.Fatalf("Failed to generate a new authority: %v", err)
		}
		pubKeys[i] = &auth[i].Pk
	}

	sampler := sample.NewUniformRange(big.NewInt(1), big.NewInt(2))
	randInt, err := sampler.Sample()
	fmt.Println(randInt)
	//if err != nil {
	//	t.Fatalf("Failed to sample message: %v", err)
	//}
	msg := new(bn256.GT).ScalarBaseMult(randInt)
	fmt.Println(msg)

	//policyVec := data.Vector([]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
	policyVec := data.Vector([]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)})

	if err != nil {
		t.Fatalf("Failed to sample policy vector: %v", err)
	}

	cipher, err := d.Encrypt(msg, policyVec, pubKeys)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	userGID := "someGID"
	//userVec := data.Vector([]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
	userVec := data.Vector([]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)})

	userKeys := make(data.MatrixG2, vecLen)
	for i:=0; i<vecLen; i++ {
		userKeys[i], err = auth[i].Keygen(userVec, pubKeys, userGID)
		if err != nil {
			t.Fatalf("Failed to generate a user key: %v", err)
		}
	}

	dec, err := d.Decrypt(cipher, userKeys, userVec, userGID)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, dec)
	fmt.Println(msg)
	fmt.Println(dec)

}
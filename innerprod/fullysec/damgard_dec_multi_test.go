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

package fullysec_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func testFullySecDamgardDecMultiFromParam(t *testing.T, param damgardTestParam) {
	// choose parameters
	numOfClients := 10
	l := 2
	bound := big.NewInt(1024)
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)

	// create a (non-decentralized) multi-input scheme as the underlying scheme
	// for the decentralization
	var damgardMulti *fullysec.DamgardMulti
	var err error
	if param.precomputed {
		// modulusLength defines the security of the scheme, the higher the better
		damgardMulti, err = fullysec.NewDamgardMultiPrecomp(numOfClients, l, param.modulusLength, bound)
	} else {
		damgardMulti, err = fullysec.NewDamgardMulti(numOfClients, l, param.modulusLength, bound)
	}
	assert.NoError(t, err)

	// we simulate different independent, decentralized clients and
	// we collect all of their public keys
	clients := make([]*fullysec.DamgardDecMultiClient, numOfClients)
	pubKeys := make([]*big.Int, numOfClients)
	for i := 0; i < numOfClients; i++ {
		clients[i], err = fullysec.NewDamgardDecMultiClient(i, damgardMulti)
		assert.NoError(t, err)
		pubKeys[i] = clients[i].ClientPubKey
	}

	// each client makes a private partial key out of the public keys and
	// create its own secret key for the encryption of a vector
	secKeys := make([]*fullysec.DamgardDecMultiSecKey, numOfClients)
	for i := 0; i < numOfClients; i++ {
		err = clients[i].SetShare(pubKeys)
		if err != nil {
			t.Fatalf("Error during share generation: %v", err)
		}

		secKeys[i], err = clients[i].GenerateKeys()
		if err != nil {
			t.Fatalf("Error during secret keys generation: %v", err)
		}
	}

	// each client encrypts its own vector x_i
	ciphertexts := make([]data.Vector, numOfClients)
	collectedX := make([]data.Vector, numOfClients) // for checking whether encrypt/decrypt works properly
	for i := 0; i < numOfClients; i++ {
		x, err := data.NewRandomVector(l, sampler) // x possessed and chosen by encryptors[i]
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		collectedX[i] = x

		c, err := clients[i].Encrypt(x, secKeys[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
		ciphertexts[i] = c
	}

	// pick a matrix that represent the collection of inner-product vectors y_i
	y, err := data.NewRandomMatrix(numOfClients, l, sampler)
	assert.NoError(t, err)

	partKeys := make([]*fullysec.DamgardDecMultiDerivedKeyPart, numOfClients)
	for i := 0; i < numOfClients; i++ {
		partKeys[i], err = clients[i].DeriveKeyShare(secKeys[i], y)
		if err != nil {
			t.Fatalf("Error during derivation of key: %v", err)
		}
	}

	// we simulate the decryptor
	decryptor := fullysec.NewDamgardDecMultiDec(damgardMulti)

	// decryptor decrypts the value
	xy, err := decryptor.Decrypt(ciphertexts, partKeys, y)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// we check if the decrypted value is correct
	xMatrix, err := data.NewMatrix(collectedX)
	if err != nil {
		t.Fatalf("Error during collection of vectors to be encrypted: %v", err)
	}
	xyCheck, err := xMatrix.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation: %v", err)
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

func TestFullySec_DamgardDecMulti(t *testing.T) {
	params := []damgardTestParam{{name: "random", modulusLength: 512, precomputed: false},
		{name: "precomputed", modulusLength: 2048, precomputed: true}}

	for _, param := range params {
		t.Run(param.name, func(t *testing.T) {
			testFullySecDamgardDecMultiFromParam(t, param)
		})
	}
}

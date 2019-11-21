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

func testFullySecDamgardMultiDDHFromParam(t *testing.T, param damgardTestParam) {
	// choose meta-parameters for the scheme
	numClients := 6
	l := 5
	bound := big.NewInt(1024)
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)

	// build the central authority for the scheme
	var damgardMulti *fullysec.DamgardMulti
	var err error
	if param.precomputed {
		// modulusLength defines the security of the scheme, the higher the better
		damgardMulti, err = fullysec.NewDamgardMultiPrecomp(numClients, l, param.modulusLength, bound)
	} else {
		damgardMulti, err = fullysec.NewDamgardMulti(numClients, l, param.modulusLength, bound)
	}
	if err != nil {
		t.Fatalf("Failed to initialize multi input inner product: %v", err)
	}

	// we simulate different clients which might be on different machines (this means "multi-input"),
	clients := make([]*fullysec.DamgardMultiClient, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = fullysec.NewDamgardMultiClientFromParams(bound, damgardMulti.Params)
	}

	// the central authority generates keys for all the clients
	secKeys, err := damgardMulti.GenerateMasterKeys()

	// pick a matrix that represent the collection of inner-product vectors y_i
	y, err := data.NewRandomMatrix(numClients, l, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	// each client encrypts its vector x_i
	collectedX := make([]data.Vector, numClients) // solely for checking whether Encrypt/Decrypt works properly
	ciphertexts := make([]data.Vector, numClients)
	for i := 0; i < numClients; i++ {
		x, err := data.NewRandomVector(l, sampler) // x_i possessed and chosen by client[i]
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		collectedX[i] = x
		c, err := clients[i].Encrypt(x, secKeys.Mpk[i], secKeys.Otp[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
		ciphertexts[i] = c
	}

	// central authority derives the key for the decryptor
	derivedKey, err := damgardMulti.DeriveKey(secKeys, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// we simulate the decryptor
	decryptor := fullysec.NewDamgardMultiFromParams(numClients, bound, damgardMulti.Params)

	// decryptor decrypts the value
	xy, err := decryptor.Decrypt(ciphertexts, derivedKey, y)
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

func TestFullySec_DamgardMultiDDH(t *testing.T) {
	params := []damgardTestParam{{name: "random", modulusLength: 512, precomputed: false},
		{name: "precomputed", modulusLength: 2048, precomputed: true}}

	for _, param := range params {
		t.Run(param.name, func(t *testing.T) {
			testFullySecDamgardMultiDDHFromParam(t, param)
		})
	}
}

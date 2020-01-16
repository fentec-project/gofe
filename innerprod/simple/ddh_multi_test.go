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

package simple_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func testSimpleMultiDDHFromParam(t *testing.T, param ddhTestParam) {
	// choose meta-parameters for the scheme
	numOfSlots := 2
	l := 3
	bound := big.NewInt(1000)
	sampler := sample.NewUniform(bound)

	// build the central authority for the scheme
	var multiDDH *simple.DDHMulti
	var err error
	if param.precomputed {
		// modulusLength defines the security of the scheme, the higher the better
		multiDDH, err = simple.NewDDHMultiPrecomp(numOfSlots, l, param.modulusLength, bound)
	} else {
		multiDDH, err = simple.NewDDHMulti(numOfSlots, l, param.modulusLength, bound)
	}
	if err != nil {
		t.Fatalf("Failed to initialize multi input inner product: %v", err)
	}

	// the central authority generates keys for all the clients
	pubKey, secKey, err := multiDDH.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// pick a matrix that represent the collection of inner-product vectors y_i
	y, err := data.NewRandomMatrix(numOfSlots, l, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	// we simulate different clients encrypting which might be on different machines (this means "multi-input"),
	// ciphertexts are then collected by decryptor and inner-product over vectors from all encryptors is computed
	clients := make([]*simple.DDHMultiClient, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
		clients[i] = simple.NewDDHMultiClient(multiDDH.Params)
	}

	// central authority derives the key for the decryptor
	derivedKey, err := multiDDH.DeriveKey(secKey, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// each client encrypts its vector x_i
	collectedX := make([]data.Vector, numOfSlots) // for checking whether encrypt/decrypt works properly
	ciphertexts := make([]data.Vector, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
		x, err := data.NewRandomVector(l, sampler) // x possessed and chosen by clients[i]
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		collectedX[i] = x

		c, err := clients[i].Encrypt(x, pubKey[i], secKey.OtpKey[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
		ciphertexts[i] = c
	}

	xMatrix, err := data.NewMatrix(collectedX)
	if err != nil {
		t.Fatalf("Error during collection of vectors to be encrypted: %v", err)
	}

	xyCheck, err := xMatrix.Dot(y)
	xyCheck.Mod(xyCheck, bound)
	if err != nil {
		t.Fatalf("Error during inner product calculation: %v", err)
	}

	// we simulate the decryptor
	decryptor := simple.NewDDHMultiFromParams(numOfSlots, multiDDH.Params)

	ciphertextMatrix, err := data.NewMatrix(ciphertexts)
	if err != nil {
		t.Fatalf("Error during collection of ciphertexts: %v", err)
	}

	// decryptor decrypts the value
	xy, err := decryptor.Decrypt(ciphertextMatrix, derivedKey, y)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// we check if the decrypted value is correct
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

func TestSimple_MultiDDH(t *testing.T) {
	params := []ddhTestParam{{name: "random", modulusLength: 512, precomputed: false},
		{name: "precomputed", modulusLength: 2048, precomputed: true}}

	for _, param := range params {
		t.Run(param.name, func(t *testing.T) {
			testSimpleMultiDDHFromParam(t, param)
		})
	}
}

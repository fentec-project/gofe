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

func TestFullySec_DamgardMultiDDH(t *testing.T) {
	// choose meta-parameters for the scheme
	numOfSlots := 10
	l := 5
	bound := big.NewInt(1024)
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)
	// this parameter defines the security of the scheme, the higher the better
	modulusLength := 512

	// build the central authority for the scheme
	damgardMulti, err := fullysec.NewDamgardMulti(numOfSlots, l, modulusLength, bound)
	if err != nil {
		t.Fatalf("Failed to initialize multi input inner product: %v", err)
	}

	// we simulate different clients which might be on different machines (this means "multi-input"),
	clients := make([]*fullysec.DamgardMultiClient, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
		clients[i] = fullysec.NewDamgardMultiClientFromParams(bound, damgardMulti.Params)
	}

	// the central authority generates keys for all the clients
	secKeys, err := damgardMulti.GenerateMasterKeys()

	// pick a matrix that represent the collection of inner-product vectors y_i
	y, err := data.NewRandomMatrix(numOfSlots, l, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	// each client encrypts its vector x_i
	collectedX := make([]data.Vector, numOfSlots) // solely for checking whether Encrypt/Decrypt works properly
	ciphertexts := make([]data.Vector, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
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
	decryptor := fullysec.NewDamgardMultiFromParams(numOfSlots, bound, damgardMulti.Params)

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

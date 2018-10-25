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

func TestSimple_MultiDDH(t *testing.T) {
	numOfSlots := 2
	l := 3
	bound := big.NewInt(1000)
	sampler := sample.NewUniform(bound)
	modulusLength := 64

	multiDDH, err := simple.NewDDHMulti(numOfSlots, l, modulusLength, bound)
	if err != nil {
		t.Fatalf("Failed to initialize multi input inner product: %v", err)
	}

	pubKey, secKey, err := multiDDH.GenerateMasterKeys()

	y, err := data.NewRandomMatrix(numOfSlots, l, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	// we simulate different encryptors which might be on different machines (this means "multi-input"),
	// ciphertexts are then collected by decryptor and inner-product over vectors from all encryptors is computed
	encryptors := make([]*simple.DDHMultiEnc, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
		encryptors[i] = simple.NewDDHMultiEnc(multiDDH.Params)
	}

	derivedKey, err := multiDDH.DeriveKey(secKey, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	collectedX := make([]data.Vector, numOfSlots) // for checking whether encrypt/decrypt works properly
	ciphertexts := make([]data.Vector, numOfSlots)
	for i := 0; i < numOfSlots; i++ {
		x, err := data.NewRandomVector(l, sampler) // x possessed and chosen by encryptors[i]
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		collectedX[i] = x

		c, err := encryptors[i].Encrypt(x, pubKey[i], secKey.OtpKey[i])
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

	decryptor := simple.NewDDHMultiFromParams(numOfSlots, multiDDH.Params)

	ciphertextMatrix, err := data.NewMatrix(ciphertexts)
	if err != nil {
		t.Fatalf("Error during collection of ciphertexts: %v", err)
	}

	xy, err := decryptor.Decrypt(ciphertextMatrix, derivedKey, y)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

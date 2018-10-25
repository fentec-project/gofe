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

func TestFullySec_Paillier(t *testing.T) {
	l := 50
	boundX := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
	boundY := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)

	samplerX := sample.NewUniformRange(new(big.Int).Neg(boundX), boundX)
	samplerY := sample.NewUniformRange(new(big.Int).Neg(boundY), boundY)
	bitLength := 512
	lambda := 128

	paillier, err := fullysec.NewPaillier(l, lambda, bitLength, boundX, boundY)
	if err != nil {
		t.Fatalf("Error during simple inner product creation: %v", err)
	}

	masterSecKey, masterPubKey, err := paillier.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Error during master key generation: %v", err)
	}

	y, err := data.NewRandomVector(l, samplerY)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	key, err := paillier.DeriveKey(masterSecKey, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	x, err := data.NewRandomVector(l, samplerX)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	// simulate the instantiation of encryptor (which should be given masterPubKey)
	encryptor := fullysec.NewPaillierFromParams(paillier.Params)

	ciphertext, err := encryptor.Encrypt(x, masterPubKey)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	xy, err := paillier.Decrypt(ciphertext, key, y)
	if err != nil {
		t.Fatalf("Error during decryption")
	}

	xyCheck, err := x.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "Original and decrypted values should match")
}

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
	"github.com/stretchr/testify/assert"
	"github.com/fentec-project/gofe/sample"
)

func TestFHIPE(t *testing.T) {
	// choose the parameters for the encryption and build the scheme
	l := 30
	bound := big.NewInt(128)

	fhipe, err := fullysec.NewFHIPE(l, bound, bound)
	if err != nil {
		t.Fatalf("Error during scheme creation: %v", err)
	}

	// generate master key
	masterSecKey, err := fhipe.GenerateMasterKey()
	if err != nil {
		t.Fatalf("Error during master key generation: %v", err)
	}

	// sample a vector that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)
	x, err := data.NewRandomVector(l, sampler)
	if err != nil {
		t.Fatalf("Error during random vector generation: %v", err)
	}

	// simulate the instantiation of an encryptor (which should know the master key)
	encryptor := fullysec.NewFHIPEFromParams(fhipe.Params)
	// encrypt the vector
	ciphertext, err := encryptor.Encrypt(x, masterSecKey)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	// sample a inner product vector
	y, err := data.NewRandomVector(l, sampler)
	if err != nil {
		t.Fatalf("Error during random vecotr generation: %v", err)
	}

	// derive a functional key for vector y
	key, err := fhipe.DeriveKey(y, masterSecKey)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// simulate a decryptor
	decryptor := fullysec.NewFHIPEFromParams(fhipe.Params)
	// decryptor decrypts the inner-product without knowing
	// vectors x and y
	xy, err := decryptor.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	xyCheck, err := x.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

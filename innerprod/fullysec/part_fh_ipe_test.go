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

func TestPartFHIPE(te *testing.T) {
	// choose parameters for the encryption and build the scheme
	l := 50
	bound := big.NewInt(100)
	boundNeg := new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1))
	sampler := sample.NewUniformRange(boundNeg, bound)
	partfhipe, err := fullysec.NewPartFHIPE(l, bound)
	if err != nil {
		te.Fatalf("Error during scheme creation: %v", err)
	}

	// choose a subspace in which encryption will be allowed
	k := 5 // dimension of the subspace
	// the subspace is given by the columns of the matrix m
	samplerM := sample.NewUniform(new(big.Int).Div(bound, big.NewInt(int64(k))))
	m, err := data.NewRandomMatrix(l, k, samplerM)
	if err != nil {
		te.Fatalf("Error during random matrix generation: %v", err)
	}
	// generate public and secret key based on matrix m
	pubKey, secKey, err := partfhipe.GenerateKeys(m)
	if err != nil {
		te.Fatalf("Error during master key generation: %v", err)
	}

	// simulate the instantiation of an encryptor
	encryptor := fullysec.NewPartFHIPEFromParams(partfhipe.Params)
	// sample a vector x that the encryptor will encrypt with public key;
	// the vector is described with k dimensional vector t such that
	// x = Mt
	sampler2 := sample.NewUniformRange(big.NewInt(-1), big.NewInt(2))
	t, err := data.NewRandomVector(k, sampler2)
	if err != nil {
		te.Fatalf("Error during random vector generation: %v", err)
	}

	// encrypt the vector
	ciphertextMt, err := encryptor.Encrypt(t, pubKey)
	if err != nil {
		te.Fatalf("Error during encryption: %v", err)
	}

	// owner of the secret key key encrypt an arbitrary vector
	x, err := data.NewRandomVector(l, sampler)
	if err != nil {
		te.Fatalf("Error during random vector generation: %v", err)
	}
	ciphertextX, err := partfhipe.SecEncrypt(x, pubKey, secKey)
	if err != nil {
		te.Fatalf("Error during encryption with secret key: %v", err)
	}

	// sample an inner product vector
	y, err := data.NewRandomVector(l, sampler)
	if err != nil {
		te.Fatalf("Error during random vecotr generation: %v", err)
	}

	// derive a functional key for vector y
	feKey, err := partfhipe.DeriveKey(y, secKey)
	if err != nil {
		te.Fatalf("Error during key derivation: %v", err)
	}

	// simulate a decryptor
	decryptor := fullysec.NewPartFHIPEFromParams(partfhipe.Params)
	// decryptor decrypts the inner-product yMt without knowing
	// vectors Mt and y
	yMt, err := decryptor.Decrypt(ciphertextMt, feKey)
	if err != nil {
		te.Fatalf("Error during decryption: %v", err)
	}
	// and decrypts the inner-product xy without knowing
	// vectors x and y
	yx, err := decryptor.Decrypt(ciphertextX, feKey)
	if err != nil {
		te.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the results
	Mt, err := m.MulVec(t)
	yMtCheck, err := y.Dot(Mt)
	if err != nil {
		te.Fatalf("Error calculating the inner product: %v", err)
	}
	yxCheck, err := y.Dot(x)
	if err != nil {
		te.Fatalf("Error calculating the inner product: %v", err)
	}
	assert.Equal(te, yMt.Cmp(yMtCheck), 0, "obtained incorrect inner product")
	assert.Equal(te, yx.Cmp(yxCheck), 0, "obtained incorrect inner product")
}

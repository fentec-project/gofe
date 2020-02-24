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

package quadratic_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/quadratic"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestQuad(t *testing.T) {
	// choose parameters for the encryption and build the scheme
	n := 10
	m := 8
	bound := big.NewInt(100)
	q, err := quadratic.NewQuad(n, m, bound)
	if err != nil {
		t.Fatalf("error when creating scheme: %v", err)
	}

	// generate public and secret key
	pubKey, secKey, err := q.GenerateKeys()
	if err != nil {
		t.Fatalf("error when generating keys: %v", err)
	}

	// sample vectors x and y that the encryptor will encrypt with public key;
	boundNeg := new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1))
	sampler := sample.NewUniformRange(boundNeg, bound)
	x, err := data.NewRandomVector(n, sampler)
	if err != nil {
		t.Fatalf("error when generating random vector: %v", err)
	}
	y, err := data.NewRandomVector(m, sampler)
	if err != nil {
		t.Fatalf("error when generating random vector: %v", err)
	}

	// simulate an encryptor that encrypts the two random vectors
	encryptor := quadratic.NewQuadFromParams(q.Params)
	c, err := encryptor.Encrypt(x, y, pubKey)
	if err != nil {
		t.Fatalf("error when encrypting: %v", err)
	}

	// derive a functional encryption key for a random matrix f
	f, err := data.NewRandomMatrix(n, m, sampler)
	if err != nil {
		t.Fatalf("error when generating random matrix: %v", err)
	}
	feKey, err := q.DeriveKey(secKey, f)
	if err != nil {
		t.Fatalf("error when deriving key: %v", err)
	}

	// simulate a decryptor that using FE key decrypt the x^T * f * y
	// without knowing x and y
	dec, err := q.Decrypt(c, feKey, f)
	if err != nil {
		t.Fatalf("error when decrypting: %v", err)
	}

	// check the correctness of the result
	check, err := f.MulXMatY(x, y)
	if err != nil {
		t.Fatalf("error when computing x*F*y: %v", err)
	}
	assert.Equal(t, check, dec, "Decryption wrong")
}

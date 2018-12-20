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
	"github.com/fentec-project/bn256"
)

func Test_DMCFE(t *testing.T) {
	numClients := 3
	clients := make([]*fullysec.DMCFEClient, numClients)
	sumT := data.NewConstantMatrix(2, 2, big.NewInt(0))

	// Generate one matrix per client - the sum of matrices needs to be 0 (modulo order of the group).
	// In real world setting matrices should be generated using secure multi-party computation. However,
	// a new scheme is coming which won't require multi-party computation.
	lim := new(big.Int).Div(bn256.Order, big.NewInt(int64(numClients)))
	sampler := sample.NewUniform(lim)
	for i := 0; i < numClients; i++ {
		T, err := data.NewRandomMatrix(2, 2, sampler)
		if err != nil {
			t.Fatalf("error when creating random matrix: %v", err)
		}
		if i < numClients-1 {
			sumT, err = sumT.Add(T)
			if err != nil {
				t.Fatalf("error when adding matrices: %v", err)
			}
		} else {
			m := data.NewConstantMatrix(2, 2, bn256.Order)
			T, err = m.Sub(sumT)
			if err != nil {
				t.Fatalf("error when subtracting matrices: %v", err)
			}
		}
		c, err := fullysec.NewDMCFEClient(i, T)
		if err != nil {
			t.Fatalf("could not instantiate fullysec.Client: %v", err)
		}
		clients[i] = c
	}

	label := "some label"
	bound := big.NewInt(1000)
	sampler1 := sample.NewUniform(bound)
	y, err := data.NewRandomVector(numClients, sampler1)
	if err != nil {
		t.Fatalf("could not create random vector: %v", err)
	}
	x, err := data.NewRandomVector(numClients, sampler1)
	if err != nil {
		t.Fatalf("could not create random vector: %v", err)
	}

	xy, err := x.Dot(y)
	if err != nil {
		t.Fatalf("could not compute inner product: %v", err)
	}

	ciphers := make([]*bn256.G1, numClients)
	keyShares := make([]data.VectorG2, numClients)
	for i := 0; i < numClients; i++ {
		c, err := clients[i].Encrypt(x[i], label)
		if err != nil {
			t.Fatalf("could not encrypt: %v", err)
		}
		ciphers[i] = c

		keyShare, err := clients[i].GenerateKeyShare(y)
		if err != nil {
			t.Fatalf("could not generate key share: %v", err)
		}
		keyShares[i] = keyShare
	}

	bound.Mul(bound, bound)
	bound.Mul(bound, big.NewInt(int64(numClients))) // numClients * (coordinate_bound)^2
	dec := fullysec.NewDMCFEDecryptor(y, label, ciphers, keyShares, bound)
	d, err := dec.Decrypt()
	if err != nil {
		t.Fatalf("error when decrypting: %v", err)
	}

	assert.Equal(t, d, xy, "Decryption wrong")
}

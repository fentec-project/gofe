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

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
	"github.com/pkg/errors"
)

func Test_DMCFE(t *testing.T) {
	numClients := 100
	clients := make([]*fullysec.DMCFEClient, numClients)

	pubT := make([]data.Matrix, numClients)
	var err error
	// create clients and make a slice of their public values
	for i := 0; i < numClients; i++ {
		c, err := fullysec.NewDMCFEClient(i)
		if err != nil {
			t.Fatalf("could not instantiate fullysec.Client: %v", err)
		}
		clients[i] = c
		pubT[i] = c.TPub
	}

	// based on public values of each client create private matrices T_i summing to 0
	for i := 0; i < numClients; i++ {
		err = clients[i].SetT(pubT)
		if err != nil {
			panic(errors.Wrap(err, "could not create private values"))
		}
	}

	// now that the clients have agreed on secret keys they can encrypt a vector in
	// a decentralized way and create partial keys such that only with all of them
	// the decryption of the inner product is possible
	label := "some label"
	bound := big.NewInt(2)
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

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

package decentralized_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	//"github.com/stretchr/testify/assert"
	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/innerprod/decentralized"
)

func Test_DMFCE(t *testing.T) {
	numClients := 3
	clients := make([]*decentralized.Client, numClients)
	sumT, err := data.NewConstantMatrix(2, 2, big.NewInt(0))
	if err != nil {
		t.Fatalf("error when initializing constant matrix: %v", err)
	}

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
			t.Log(T)
		} else {
			m, err := data.NewConstantMatrix(2, 2, bn256.Order)
			if err != nil {
				t.Fatalf("error when initializing constant matrix: %v", err)
			}

			T, err = m.Sub(sumT)
			if err != nil {
				t.Fatalf("error when subtracting matrices: %v", err)
			}
		}
		c, err := decentralized.NewClient(i, T)
		if err != nil {
			t.Fatalf("could not instantiate decentralized.Client: %v", err)
		}
		clients[i] = c
	}

	/*
		checkT, _ := data.NewConstantMatrix(2, 2, big.NewInt(0))
		for i := 0; i < len(clients); i++ {
			checkT, _ = checkT.Add(clients[i].T)
		}
		t.Log("??/////-----------")
		t.Log(checkT)
		t.Log(bn256.Order)
	*/

	label := "some label"
	y, err := data.NewRandomVector(numClients, sampler)
	if err != nil {
		t.Fatalf("could not create random vector: %v", err)
	}

	ciphertexts := make([]*bn256.G1, numClients)
	keyShares := make([]data.VectorG2, numClients)
	for i := 0; i < numClients; i++ {
		c, err := clients[i].Encrypt(big.NewInt(3), label)
		if err != nil {
			t.Fatalf("could not encrypt: %v", err)
		}
		ciphertexts[i] = c

		keyShare, err := clients[0].GenerateKeyShare(y)
		if err != nil {
			t.Fatalf("could not generate key share: %v", err)
		}
		keyShares[i] = keyShare
	}

}

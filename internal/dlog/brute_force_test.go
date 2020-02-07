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

package dlog

import (
	"math/big"
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestBruteForceBN256(t *testing.T) {
	bound := big.NewInt(1000)
	sampler := sample.NewUniform(bound)
	xCheck, err := sampler.Sample()
	if err != nil {
		t.Fatalf("error in random value generation: %v", err)
	}

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)
	h := new(bn256.GT).ScalarMult(g, xCheck)

	x, err := bruteForceBN256(h, g, bound)
	if err != nil {
		t.Fatalf("error in brute force algorithm: %v", err)
	}
	assert.Equal(t, xCheck.Cmp(x), 0, "obtained incorrect result")
}

func TestBruteForce(t *testing.T) {
	bound := big.NewInt(1000)
	sampler := sample.NewUniform(bound)
	xCheck, err := sampler.Sample()
	if err != nil {
		t.Fatalf("error in random value generation: %v", err)
	}

	key, err := keygen.NewElGamal(20)
	if err != nil {
		t.Fatalf("error in parameters generation: %v", err)
	}

	h := new(big.Int).Exp(key.G, xCheck, key.P)

	x, err := bruteForce(h, key.G, key.P, bound)
	if err != nil {
		t.Fatalf("error in brute force algorithm: %v", err)
	}
	assert.Equal(t, xCheck.Cmp(x), 0, "obtained incorrect result")
}

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
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestCalcZp_BabyStepGiantStep_ElGamal(t *testing.T) {
	modulusLength := 128

	key, err := keygen.NewElGamal(modulusLength)
	if err != nil {
		t.Fatalf("Error in ElGamal key generation: %v", err)
	}

	bound := big.NewInt(100000000)

	// first test when x is positive
	sampler := sample.NewUniformRange(big.NewInt(2), bound)
	xCheck, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h := new(big.Int).Exp(key.G, xCheck, key.P)

	calc, err := NewCalc().InZp(key.P, nil)
	if err != nil {
		t.Fatal("Error in creation of new CalcZp:", err)
	}
	calc = calc.WithBound(bound)
	x, err := calc.BabyStepGiantStep(h, key.G)
	if err != nil {
		t.Fatalf("Error in baby step - giant step algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x, "BabyStepGiantStep result is wrong")

	// second test when the answer can also be negative
	sampler = sample.NewUniformRange(new(big.Int).Neg(bound), bound)
	xCheck, err = sampler.Sample()
	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h = internal.ModExp(key.G, xCheck, key.P)

	calc = calc.WithNeg()

	x, err = calc.BabyStepGiantStep(h, key.G)
	if err != nil {
		t.Fatalf("Error in baby step - giant step algorithm: %v", err)
	}
	assert.Equal(t, xCheck.Cmp(x), 0, "BabyStepGiantStep result is wrong")
}

func TestCalcBN256_BabyStepGiantStep(t *testing.T) {

	bound := big.NewInt(100000000)
	sampler := sample.NewUniformRange(new(big.Int).Neg(bound), bound)

	xCheck, err := sampler.Sample()
	if err != nil {
		t.Fatalf("error when generating random number: %v", err)
	}

	g := new(bn256.GT).ScalarBaseMult(big.NewInt(1))
	h := new(bn256.GT)
	if xCheck.Sign() == 1 {
		h.ScalarMult(g, xCheck)
	} else {
		xCheckNeg := new(big.Int).Neg(xCheck)
		h.ScalarMult(g, xCheckNeg)
		h.Neg(h)
	}

	calc := NewCalc().InBN256().WithBound(bound).WithNeg()
	x, err := calc.BabyStepGiantStep(h, g)
	if err != nil {
		t.Fatalf("Error in baby step - giant step algorithm: %v", err)
	}

	assert.Equal(t, xCheck.Cmp(x), 0, "BabyStepGiantStep in BN256 returns wrong dlog")
}

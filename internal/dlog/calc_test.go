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

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/stretchr/testify/assert"
	emmy "github.com/xlab-si/emmy/crypto/common"
)

//// TODO not really using schnorr group anymore...
//func TestCalcZp_BabyStepGiantStep_SchnorrGroup(t *testing.T) {
//	key := get_params()
//	bound := new(big.Int).Sqrt(key.p)
//	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), bound)
//	if err != nil {
//		t.Fatalf("Error during random int generation: %v", err)
//	}
//
//	calc, err := NewCalc().InZp(key.p, key.order)
//	if err != nil {
//		t.Fatal("Error in creation of new CalcZp:", err)
//	}
//
//	h := new(big.Int).Exp(key.g, xCheck, key.p)
//	x, err := calc.WithBound(nil).BabyStepGiantStep(h, key.g)
//	if err != nil {
//		t.Fatalf("Error in BabyStepGiantStep algorithm: %v", err)
//	}
//	assert.Equal(t, xCheck, x, "BabyStepGiantStep result is wrong")
//
//}

func TestCalcZp_BabyStepGiantStep_ElGamal(t *testing.T) {
	modulusLength := 44

	key, err := keygen.NewElGamal(modulusLength)
	if err != nil {
		t.Fatalf("Error in ElGamal key generation: %v", err)
	}

	//order := new(big.Int).Sub(key.P, big.NewInt(1))
	bound := new(big.Int).Sqrt(key.P)

	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), bound)
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
}

func TestCalcBN256_BabyStepGiantStep(t *testing.T) {
	xCheck := big.NewInt(10000000)
	bound := big.NewInt(10000000)
	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)
	h := new(bn256.GT).ScalarMult(g, xCheck)

	calc := NewCalc().InBN256().WithBound(bound)
	x, err := calc.BabyStepGiantStep(h, g)
	if err != nil {
		t.Fatalf("Error in baby step - giant step algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x, "BabyStepGiantStep in BN256 returns wrong dlog")
}

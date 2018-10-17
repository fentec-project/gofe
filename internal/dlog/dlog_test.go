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
	"time"

	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/stretchr/testify/assert"
	emmy "github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/schnorr"
)

type params struct {
	p, order, g *big.Int
}

func getParams() (*params, error) {
	key, err := keygen.NewElGamal(20)
	if err != nil {
		return nil, err
	}

	return &params{
		p:     key.P,
		order: new(big.Int).Sub(key.P, big.NewInt(1)),
		g:     key.G,
	}, nil
}

func TestDLog(t *testing.T) {
	params, err := getParams()
	if err != nil {
		t.Fatalf("Error during parameters generation: %v", err)
	}

	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), params.order)

	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h := new(big.Int).Exp(params.g, xCheck, params.p)

	calc, _ := NewCalc().InZp(params.p, params.order)
	x1, err := calc.WithBound(nil).BabyStepGiantStep(h, params.g)
	if err != nil {
		t.Fatalf("Error in BabyStepGiantStep algorithm: %v", err)
	}

	x2, err := pollardRhoParallel(h, params.g, params.p, params.order)

	if err != nil {
		t.Fatalf("Error in Pollard rho algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x1, "BabyStepGiantStep result is wrong")
	assert.Equal(t, xCheck, x2, "pollardRho result is wrong")
	//fmt.Printf("BabyStepGiantStep time: %.5f s, pollardRho time: %.5f s\n", elapsed1.Seconds(), elapsed2.Seconds())
	//fmt.Printf("BabyStepGiantStep speedup: %.3f\n", elapsed2.Seconds()/elapsed1.Seconds())
}

//TODO
func BenchmarkDLog(b *testing.B) {
	modulusLength := 32
	times := 100
	tm := time.Now()

	t1 := 0.0
	t2 := 0.0
	t3 := 0.0

	for i := 0; i < times; i++ {
		key, _ := schnorr.NewGroup(modulusLength)
		order := key.Q
		xCheck, _ := emmy.GetRandomIntFromRange(big.NewInt(2), order)
		h := new(big.Int).Exp(key.G, xCheck, key.P)

		calc, _ := NewCalc().InZp(key.P, nil)
		tm = time.Now()
		calc.WithBound(nil).BabyStepGiantStep(h, key.G)
		t1 += time.Since(tm).Seconds()

		calc, _ = NewCalc().InZp(key.P, order)
		tm = time.Now()
		calc.WithBound(nil).BabyStepGiantStep(h, key.G)
		t2 += time.Since(tm).Seconds()

		tm = time.Now()
		pollardRhoParallel(h, key.G, key.P, order)
		t3 += time.Since(tm).Seconds()

		//if i%10 == 0 {
		//	fmt.Printf("Ran %d times.\n", i)
		//}
	}

	fl := float64(times)
	t1 /= fl
	t2 /= fl
	t3 /= fl

	//fmt.Printf("%.5f s\n%.5f s\n%.5f s\n", t1, t2, t3)
}

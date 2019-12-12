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

	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
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
		order: key.Q,
		g:     key.G,
	}, nil
}

func TestDLog(t *testing.T) {
	params, err := getParams()
	if err != nil {
		t.Fatalf("Error during parameters generation: %v", err)
	}

	sampler := sample.NewUniformRange(big.NewInt(2), params.order)
	xCheck, err := sampler.Sample()

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

	assert.Equal(t, xCheck.Cmp(x1), 0, "BabyStepGiantStep result is wrong")
	assert.Equal(t, xCheck.Cmp(x2), 0, "pollardRho result is wrong")
}

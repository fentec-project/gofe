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

package sample_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestNewNormalDouble(t *testing.T) {
	var tests = []struct {
		name       string
		sigma      *big.Float
		sigmaFirst *big.Float
		n          uint
		expect     paramBounds
	}{
		{
			name:       "SigmaFirst=1, sigma=1.5",
			sigmaFirst: big.NewFloat(1),
			sigma:      big.NewFloat(1.5),
			n:          256,
			expect: paramBounds{
				meanLow:  -0.5,
				meanHigh: 0.5,
				varLow:   90,
				varHigh:  110,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := sample.NewNormalDouble(test.sigma, test.n, test.sigmaFirst)
			assert.Error(t, err)
		})
	}
}

func TestNormalDouble(t *testing.T) {
	var tests = []struct {
		name       string
		sigma      *big.Float
		sigmaFirst *big.Float
		n          uint
		expect     paramBounds
	}{
		{
			name:       "SigmaFirst=1, sigma10",
			sigmaFirst: big.NewFloat(1),
			sigma:      big.NewFloat(10),
			n:          256,
			expect: paramBounds{
				meanLow:  -0.5,
				meanHigh: 0.5,
				varLow:   90,
				varHigh:  110,
			},
		},
		{
			name:       "SigmaFirst=1.5, sigma9",
			sigmaFirst: big.NewFloat(1.5),
			sigma:      big.NewFloat(9),
			n:          256,
			expect: paramBounds{
				meanLow:  -0.5,
				meanHigh: 0.5,
				varLow:   70,
				varHigh:  100,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sampler, err := sample.NewNormalDouble(test.sigma, test.n, test.sigmaFirst)
			assert.NoError(t, err)
			testNormalSampler(
				t,
				sampler,
				test.expect,
			)
		})
	}
}

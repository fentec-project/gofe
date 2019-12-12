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

func TestNewNormalDoubleConstant(t *testing.T) {
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

func TestNormalDoubleConstant(t *testing.T) {
	//sigmaCDT, _ := new(big.Float).SetString("0.84932180028801904272150283410")

	var tests = []struct {
		k		   *big.Int
		name       string
		expect     paramBounds
	}{
		{
			name:   "sigma= 1 * sqrt(1/(2*ln(2)))",
			k:      big.NewInt(1),
			expect: paramBounds{
				meanLow:  -0.2,
				meanHigh: 0.2,
				varLow:   0.5,
				varHigh:  1.5,
			},
		},
		{
			name:   "sigma= 10 * sqrt(1/(2*ln(2)))",
			k:      big.NewInt(10),
			expect: paramBounds{
				meanLow:  -2,
				meanHigh: 2,
				varLow:   64,
				varHigh:  81,
			},
		},
		//{
		//	name:   "sigma= 1000 * sqrt(1/(2*ln(2)))",
		//	k:      big.NewInt(1000),
		//	expect: paramBounds{
		//		meanLow:  -20,
		//		meanHigh: 20,
		//		varLow:   640000,
		//		varHigh:  810000,
		//	},
		//},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sampler, err := sample.NewNormalDoubleConstant(test.k)
			assert.NoError(t, err)
			testNormalSampler(
				t,
				sampler,
				test.expect,
			)
		})
	}
}

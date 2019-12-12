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
)

func TestNormalDoubleConstant(t *testing.T) {
	sigmaCDTSquare := 0.84932180028801904272150283410
	sigmaCDTSquare *= sigmaCDTSquare
	var tests = []struct {
		k      *big.Int
		name   string
		expect paramBounds
	}{
		{
			name: "sigma= 1 * sqrt(1/(2*ln(2)))",
			k:    big.NewInt(1),
			expect: paramBounds{
				meanLow:  -0.2,
				meanHigh: 0.2,
				varLow:   sigmaCDTSquare - 0.02,
				varHigh:  sigmaCDTSquare + 0.02,
			},
		},
		{
			name: "sigma= 10 * sqrt(1/(2*ln(2)))",
			k:    big.NewInt(10),
			expect: paramBounds{
				meanLow:  -2,
				meanHigh: 2,
				varLow:   100 * (sigmaCDTSquare - 0.02),
				varHigh:  100 * (sigmaCDTSquare + 0.02),
			},
		},
		{
			name: "sigma= 1000 * sqrt(1/(2*ln(2)))",
			k:    big.NewInt(1000),
			expect: paramBounds{
				meanLow:  -20,
				meanHigh: 20,
				varLow:   1000000 * (sigmaCDTSquare - 0.02),
				varHigh:  1000000 * (sigmaCDTSquare + 0.02),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sampler := sample.NewNormalDoubleConstant(test.k)
			testNormalSampler(
				t,
				sampler,
				test.expect,
			)
		})
	}
}

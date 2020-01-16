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

func TestNormalCumulative(t *testing.T) {
	var tests = []struct {
		name     string
		sigma    *big.Float
		n        uint
		twoSided bool
		expect   paramBounds
	}{
		{
			name:     "TwoSided, sigma 10",
			sigma:    big.NewFloat(10),
			n:        256,
			twoSided: true,
			expect: paramBounds{
				meanLow:  -2,
				meanHigh: 2,
				varLow:   90,
				varHigh:  110,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testNormalSampler(
				t,
				sample.NewNormalCumulative(test.sigma, test.n, test.twoSided),
				test.expect,
			)
		})
	}
}

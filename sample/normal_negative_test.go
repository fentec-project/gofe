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
	"fmt"
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/sample"
)

func TestNormalNegative(t *testing.T) {
	var tests = []struct {
		sigma  *big.Float
		n      uint
		expect paramBounds
	}{
		{
			sigma: big.NewFloat(10),
			n:     256,
			expect: paramBounds{
				meanLow:  -2,
				meanHigh: 2,
				varLow:   90,
				varHigh:  110,
			},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Sigma=%v", test.sigma), func(t *testing.T) {
			testNormalSampler(t, sample.NewNormalNegative(test.sigma, test.n), test.expect)
		})
	}
}

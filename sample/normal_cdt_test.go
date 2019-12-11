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
	"testing"

	"github.com/fentec-project/gofe/sample"
)

func TestNormalCDT(t *testing.T) {
	var tests = []struct {
		name     string
		expect   paramBounds
	}{
		{
			name:     "CDT",
			expect: paramBounds{
				meanLow:  0,
				meanHigh: 2,
				varLow:   0,
				varHigh:  2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testNormalSampler(
				t,
				sample.NewNormalCDT(),
				test.expect,
			)
		})
	}

}

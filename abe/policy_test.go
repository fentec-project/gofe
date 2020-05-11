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

package abe

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
)

func TestBooleanToMsp(t *testing.T) {
	// create as msp struct out of a boolean expression
	p := big.NewInt(7)
	msp, err := BooleanToMSP("1 AND (((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", true)
	if err != nil {
		t.Fatalf("Error while processing a boolean expression: %v", err)
	}

	// check if having attributes 1, 7 and 9 satisfies the expression, i.e. entries 0, 2, 4
	// of a msp matrix span vector [1, 1,..., 1], using Gaussian elimination
	v := make(data.Vector, len(msp.Mat[0]))
	for i := 0; i < len(v); i++ {
		v[i] = big.NewInt(1)
	}
	m := make(data.Matrix, 3)
	m[0] = msp.Mat[0]
	m[1] = msp.Mat[2]
	m[2] = msp.Mat[4]

	x, err := data.GaussianEliminationSolver(m.Transpose(), v, p)
	if err != nil {
		t.Fatalf("Error finding a vector: %v", err)
	}
	assert.NotNil(t, x)

	// check if an error is generated if the boolean expression is not in a correct form
	_, err = BooleanToMSP("1 AND ((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", true)
	assert.Error(t, err)
}

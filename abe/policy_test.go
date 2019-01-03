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
	"github.com/fentec-project/gofe/sample"
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

	x, err := gaussianElimination(m.Transpose(), v, p)
	if err != nil {
		t.Fatalf("Error finding a vector: %v", err)
	}
	assert.NotNil(t, x)

	// check if an error is generated if the boolean expression is not in a correct form
	_, err = BooleanToMSP("1 AND ((6 OR 7) AND (8 OR 9)) OR ((2 AND 3) OR (4 AND 5)))", true)
	assert.Error(t, err)

}

func TestGaussianElimintaion(t *testing.T) {
	// create instances mat, xTest and v for which mat * xTest = v
	// as a matrix vector multiplication over Z_p

	p := big.NewInt(17)
	sampler := sample.NewUniform(p)
	mat, err := data.NewRandomMatrix(100, 50, sampler)
	if err != nil {
		t.Fatalf("Error during matrix generation: %v", err)
	}

	xTest, err := data.NewRandomVector(50, sampler)
	if err != nil {
		t.Fatalf("Error during vector generation: %v", err)
	}

	v, err := mat.MulVec(xTest)
	if err != nil {
		t.Fatalf("Error in generating a test vector: %v", err)
	}
	v = v.Mod(p)

	// test the Gaussian elimination algorithm that given v and mat
	// finds x such that mat * x = v
	x, err := gaussianElimination(mat, v, p)
	if err != nil {
		t.Fatalf("Error in Gaussian elimination: %v", err)
	}

	// test if the obtained x is correct
	vCheck, err := mat.MulVec(x)
	if err != nil {
		t.Fatalf("Error obtainig a check value: %v", err)
	}
	vCheck = vCheck.Mod(p)
	assert.Equal(t, v, vCheck)

	// test if errors are returned if the inputs have a wrong form
	vWrong, err := data.NewRandomVector(101, sampler)
	if err != nil {
		t.Fatalf("Error during vector generation: %v", err)
	}
	_, err = gaussianElimination(mat, vWrong, p)
	assert.Error(t, err)

	matWrong := make(data.Matrix, 0)
	_, err = gaussianElimination(matWrong, v, p)
	assert.Error(t, err)
}

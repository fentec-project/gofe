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
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/fentec-project/gofe/data"
)

// MSP represents a monotone span program (MSP) describing a policy defining which
// attributes are needed to decrypt the ciphertext. It includes a matrix
// mat and a mapping from the rows of the mat to attributes. A MSP policy
// allows decryption of an entity with a set of attributes A if an only if all the
// rows of the matrix mapped to an element of A span the vector [1, 0,..., 0] (or
// vector [1, 1,..., 1] depending on the use case).
type MSP struct {
	P           *big.Int
	Mat         data.Matrix
	RowToAttrib []int
}

// BooleanToMSP takes as an input a boolean expression (without a NOT gate) and
// outputs a msp structure representing the expression, i.e. a matrix whose rows
// correspond to attributes used in the expression and with the property that a
// boolean expression assigning 1 to some attributes is satisfied iff the
// corresponding rows span a vector [1, 1,..., 1] or vector [1, 0,..., 0]
// depending if parameter convertToOnes is set to true or false. Additionally a
// vector is produced whose i-th entry indicates to which attribute the i-th row
// corresponds.
func BooleanToMSP(boolExp string, convertToOnes bool) (*MSP, error) {
	// by the Lewko-Waters algorithm we obtain a MSP struct with the property
	// that is the the boolean expression is satisfied if and only if the corresponding
	// rows of the msp matrix span the vector [1, 0,..., 0]
	vec := make(data.Vector, 1)
	vec[0] = big.NewInt(1)
	msp, _, err := booleanToMSPIterative(boolExp, vec, 1)
	if err != nil {
		return nil, err
	}

	// if convertToOnes is set to true convert the matrix to such a MSP
	// struct so that the boolean expression is satisfied iff the
	// corresponding rows span the vector [1, 1,..., 1]
	if convertToOnes {
		// create an invertible matrix that maps [1, 0,..., 0] to [1,1,...,1]
		invMat := make(data.Matrix, len(msp.Mat[0]))
		for i := 0; i < len(msp.Mat[0]); i++ {
			invMat[i] = make(data.Vector, len(msp.Mat[0]))
			for j := 0; j < len(msp.Mat[0]); j++ {
				if i == 0 || j == i {
					invMat[i][j] = big.NewInt(1)
				} else {
					invMat[i][j] = big.NewInt(0)
				}

			}
		}
		//change the msp matrix by multiplying with it the matrix invMat
		msp.Mat, err = msp.Mat.Mul(invMat)
		if err != nil {
			return nil, err
		}
	}

	return msp, nil
}

// booleanToMspIterative iteratively builds a msp structure by splitting the expression
// into two parts separated by an AND or OR gate, generating a msp structure on each of
// them, and joining both structures together. The structure is such the the boolean expression
// assigning 1 to some attributes is satisfied iff the corresponding rows span a vector
// [1, 0,..., 0]. The algorithm is known as Lewko-Waters algorithm, see Appendix G in
// https://eprint.iacr.org/2010/351.pdf.
func booleanToMSPIterative(boolExp string, vec data.Vector, c int) (*MSP, int, error) {
	boolExp = strings.TrimSpace(boolExp)
	numBrc := 0
	var boolExp1 string
	var boolExp2 string
	var c1 int
	var cOut int
	var msp1 *MSP
	var msp2 *MSP
	var err error
	found := false

	// find the main AND or OR gate and iteratively call the function on
	// both the sub-expressions
	for i, e := range boolExp {
		if e == '(' {
			numBrc++
			continue
		}
		if e == ')' {
			numBrc--
			continue
		}
		if numBrc == 0 && i < len(boolExp)-3 && boolExp[i:i+3] == "AND" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+3:]
			vec1, vec2 := makeAndVecs(vec, c)
			msp1, c1, err = booleanToMSPIterative(boolExp1, vec1, c+1)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMSPIterative(boolExp2, vec2, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
		if numBrc == 0 && i < len(boolExp)-2 && boolExp[i:i+2] == "OR" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+2:]
			msp1, c1, err = booleanToMSPIterative(boolExp1, vec, c)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMSPIterative(boolExp2, vec, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
	}

	// If the AND or OR gate is not found then there are two options,
	// either the whole expression is in brackets, or the the expression
	// is only one attribute. It neither of both is true, then
	// an error is returned while converting the expression into an
	// attribute
	if found == false {
		if boolExp[0] == '(' && boolExp[len(boolExp)-1] == ')' {
			boolExp = boolExp[1:(len(boolExp) - 1)]
			return booleanToMSPIterative(boolExp, vec, c)
		}

		attrib, err := strconv.Atoi(boolExp)
		if err != nil {
			return nil, 0, err
		}
		mat := make(data.Matrix, 1)
		mat[0] = make(data.Vector, c)
		for i := 0; i < c; i++ {
			if i < len(vec) {
				mat[0][i] = new(big.Int).Set(vec[i])
			} else {
				mat[0][i] = big.NewInt(0)
			}
		}

		rowToAttrib := make([]int, 1)
		rowToAttrib[0] = attrib
		return &MSP{Mat: mat, RowToAttrib: rowToAttrib}, c, nil
	} else {
		// otherwise we join the two msp structures into one
		mat := make(data.Matrix, len(msp1.Mat)+len(msp2.Mat))
		for i := 0; i < len(msp1.Mat); i++ {
			mat[i] = make(data.Vector, cOut)
			for j := 0; j < len(msp1.Mat[0]); j++ {
				mat[i][j] = msp1.Mat[i][j]
			}
			for j := len(msp1.Mat[0]); j < cOut; j++ {
				mat[i][j] = big.NewInt(0)
			}
		}
		for i := 0; i < len(msp2.Mat); i++ {
			mat[i+len(msp1.Mat)] = msp2.Mat[i]
		}
		rowToAttrib := append(msp1.RowToAttrib, msp2.RowToAttrib...)

		return &MSP{Mat: mat, RowToAttrib: rowToAttrib}, cOut, nil
	}
}

// makeAndVecs is a helping structure that given a vector and and counter
// creates two new vectors used whenever an AND gate is found in a iterative
// step of BooleanToMsp
func makeAndVecs(vec data.Vector, c int) (data.Vector, data.Vector) {
	vec1 := data.NewConstantVector(c+1, big.NewInt(0))
	vec2 := data.NewConstantVector(c+1, big.NewInt(0))
	for i := 0; i < len(vec); i++ {
		vec2[i].Set(vec[i])
	}
	vec1[c] = big.NewInt(-1)
	vec2[c] = big.NewInt(1)

	return vec1, vec2
}

// gaussianElimination solves a vector equation mat * x = v and finds vector x,
// using Gaussian elimination. Arithmetic operations are considered to be over
// Z_p, where p should be a prime number. If such x does not exist, then the
// function returns an error.
func gaussianElimination(mat data.Matrix, v data.Vector, p *big.Int) (data.Vector, error) {
	if len(mat) == 0 || len(mat[0]) == 0 {
		return nil, fmt.Errorf("the matrix should not be empty")
	}
	if len(mat) != len(v) {
		return nil, fmt.Errorf(fmt.Sprintf("dimensions should match: "+
			"rows of the matrix %d, length of the vector %d", len(mat), len(v)))
	}

	// we copy matrix mat into m and v into u
	cpMat := make([]data.Vector, len(mat))
	u := make(data.Vector, len(mat))
	for i := 0; i < len(mat); i++ {
		cpMat[i] = make(data.Vector, len(mat[0]))
		for j := 0; j < len(mat[0]); j++ {
			cpMat[i][j] = new(big.Int).Set(mat[i][j])
		}
		u[i] = new(big.Int).Set(v[i])
	}
	m, _ := data.NewMatrix(cpMat) // error is impossible to happen

	// m and u are transformed to be in the upper triangular form
	ret := make(data.Vector, len(mat[0]))
	h, k := 0, 0
	for h < len(m) && k < len(m[0]) {
		zero := true
		for i := h; i < len(m); i++ {
			if m[i][k].Sign() != 0 {
				m[h], m[i] = m[i], m[h]

				u[h], u[i] = u[i], u[h]
				zero = false
				break
			}
		}
		if zero {
			ret[k] = big.NewInt(0)
			k++
			continue
		}
		mHKInv := new(big.Int).ModInverse(m[h][k], p)
		for i := h + 1; i < len(m); i++ {
			f := new(big.Int).Mul(mHKInv, m[i][k])
			m[i][k] = big.NewInt(0)
			for j := k + 1; j < len(m[0]); j++ {
				m[i][j].Sub(m[i][j], new(big.Int).Mul(f, m[h][j]))
				m[i][j].Mod(m[i][j], p)
			}
			u[i].Sub(u[i], new(big.Int).Mul(f, u[h]))
			u[i].Mod(u[i], p)
		}
		k++
		h++
	}

	for i := h; i < len(m); i++ {
		if u[i].Sign() != 0 {
			return nil, fmt.Errorf("no solution")
		}
	}
	for j := k; j < len(m[0]); j++ {
		ret[j] = big.NewInt(0)
	}

	// use the upper triangular form to obtain the solution
	for i := h - 1; i >= 0; i-- {
		for j := k - 1; j >= 0; j-- {
			if ret[j] == nil {
				tmpSum, _ := m[i][j+1:].Dot(ret[j+1:])
				ret[j] = new(big.Int).Sub(u[i], tmpSum)
				mHKInv := new(big.Int).ModInverse(m[i][j], p)
				ret[j].Mul(ret[j], mHKInv)
				ret[j].Mod(ret[j], p)
				break
			}
		}
	}

	return ret, nil
}

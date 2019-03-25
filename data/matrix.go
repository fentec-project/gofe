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

package data

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/sample"
)

// Matrix wraps a slice of Vector elements. It represents a row-major.
// order matrix.
//
// The j-th element from the i-th vector of the matrix can be obtained
// as m[i][j].
type Matrix []Vector

// NewMatrix accepts a slice of Vector elements and
// returns a new Matrix instance.
// It returns error if not all the vectors have the same number of elements.
func NewMatrix(vectors []Vector) (Matrix, error) {
	l := -1
	newVectors := make([]Vector, len(vectors))

	if len(vectors) > 0 {
		l = len(vectors[0])
	}
	for i, v := range vectors {
		if len(v) != l {
			return nil, fmt.Errorf("all vectors should be of the same length")
		}
		newVectors[i] = NewVector(v)
	}

	return Matrix(newVectors), nil
}

// NewRandomMatrix returns a new Matrix instance
// with random elements sampled by the provided sample.Sampler.
// Returns an error in case of sampling failure.
func NewRandomMatrix(rows, cols int, sampler sample.Sampler) (Matrix, error) {
	mat := make([]Vector, rows)

	for i := 0; i < rows; i++ {
		vec, err := NewRandomVector(cols, sampler)
		if err != nil {
			return nil, err
		}

		mat[i] = vec
	}

	return NewMatrix(mat)
}

// NewConstantMatrix returns a new Matrix instance
// with all elements set to constant c.
func NewConstantMatrix(rows, cols int, c *big.Int) Matrix {
	mat := make([]Vector, rows)
	for i := 0; i < rows; i++ {
		mat[i] = NewConstantVector(cols, c)
	}

	return mat
}

// Rows returns the number of rows of matrix m.
func (m Matrix) Rows() int {
	return len(m)
}

// Cols returns the number of columns of matrix m.
func (m Matrix) Cols() int {
	if len(m) != 0 {
		return len(m[0])
	}

	return 0
}

// DimsMatch returns a bool indicating whether matrices
// m and other have the same dimensions.
func (m Matrix) DimsMatch(other Matrix) bool {
	return m.Rows() == other.Rows() && m.Cols() == other.Cols()
}

// GetCol returns i-th column of matrix m as a vector.
// It returns error if i >= the number of m's columns.
func (m Matrix) GetCol(i int) (Vector, error) {
	if i >= m.Cols() {
		return nil, fmt.Errorf("column index exceeds matrix dimensions")
	}

	column := make([]*big.Int, m.Rows())
	for j := 0; j < m.Rows(); j++ {
		column[j] = m[j][i]
	}

	return NewVector(column), nil
}

// Transpose transposes matrix m and returns
// the result in a new Matrix.
func (m Matrix) Transpose() Matrix {
	transposed := make([]Vector, m.Cols())
	for i := 0; i < m.Cols(); i++ {
		transposed[i], _ = m.GetCol(i)
	}

	mT, _ := NewMatrix(transposed)

	return mT
}

// CheckBound checks whether all matrix elements are strictly
// smaller than the provided bound.
// It returns error if at least one element is >= bound.
func (m Matrix) CheckBound(bound *big.Int) error {
	for _, v := range m {
		err := v.CheckBound(bound)
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckDims checks whether dimensions of matrix m match
// the provided rows and cols arguments.
func (m Matrix) CheckDims(rows, cols int) bool {
	return m.Rows() == rows && m.Cols() == cols
}

// Mod applies the element-wise modulo operation on matrix m.
// The result is returned in a new Matrix.
func (m Matrix) Mod(modulo *big.Int) Matrix {
	vectors := make([]Vector, m.Rows())

	for i, v := range m {
		vectors[i] = v.Mod(modulo)
	}

	matrix, _ := NewMatrix(vectors)

	return matrix
}

// Apply applies an element-wise function f to matrix m.
// The result is returned in a new Matrix.
func (m Matrix) Apply(f func(*big.Int) *big.Int) Matrix {
	res := make(Matrix, len(m))

	for i, vi := range m {
		res[i] = vi.Apply(f)
	}

	return res
}

// Dot calculates the dot product (inner product) of matrices m and other.
// It returns an error if m and other have different dimensions.
func (m Matrix) Dot(other Matrix) (*big.Int, error) {
	if !m.DimsMatch(other) {
		return nil, fmt.Errorf("matrices mismatch in dimensions")
	}

	r := new(big.Int)

	for i := 0; i < m.Rows(); i++ {
		prod, err := m[i].Dot(other[i])
		if err != nil {
			return nil, err
		}
		r = r.Add(r, prod)
	}

	return r, nil
}

// Add adds matrices m and other.
// The result is returned in a new Matrix.
// Error is returned if m and other have different dimensions.
func (m Matrix) Add(other Matrix) (Matrix, error) {
	if !m.DimsMatch(other) {
		return nil, fmt.Errorf("matrices mismatch in dimensions")
	}

	vectors := make([]Vector, m.Rows())

	for i, v := range m {
		vectors[i] = v.Add(other[i])
	}

	matrix, err := NewMatrix(vectors)
	if err != nil {
		return nil, err
	}
	return matrix, nil
}

// Sub adds matrices m and other.
// The result is returned in a new Matrix.
// Error is returned if m and other have different dimensions.
func (m Matrix) Sub(other Matrix) (Matrix, error) {
	if !m.DimsMatch(other) {
		return nil, fmt.Errorf("matrices mismatch in dimensions")
	}

	vecs := make([]Vector, m.Rows())

	for i, v := range m {
		vecs[i] = v.Sub(other[i])
	}

	return NewMatrix(vecs)
}

// Mul multiplies matrices m and other.
// The result is returned in a new Matrix.
// Error is returned if m and other have different dimensions.
func (m Matrix) Mul(other Matrix) (Matrix, error) {
	if m.Cols() != other.Rows() {
		return nil, fmt.Errorf("cannot multiply matrices")
	}

	prod := make([]Vector, m.Rows()) // tok vrstic kot m, tok stolpcev kot other
	for i := 0; i < m.Rows(); i++ {  // po vrsticah od m
		prod[i] = make([]*big.Int, other.Cols())
		for j := 0; j < other.Cols(); j++ {
			otherCol, _ := other.GetCol(j)
			prod[i][j], _ = m[i].Dot(otherCol)
		}
	}

	return NewMatrix(prod)
}

// MulScalar multiplies elements of matrix m by a scalar x.
// The result is returned in a new Matrix.
func (m Matrix) MulScalar(x *big.Int) Matrix {
	return m.Apply(func(i *big.Int) *big.Int {
		return new(big.Int).Mul(i, x)
	})
}

// MulVec multiplies matrix m and vector v.
// It returns the resulting vector.
// Error is returned if the number of columns of m differs from the number
// of elements of v.
func (m Matrix) MulVec(v Vector) (Vector, error) {
	if m.Cols() != len(v) {
		return nil, fmt.Errorf("cannot multiply matrix by a vector")
	}

	res := make(Vector, m.Rows())
	for i, row := range m {
		res[i], _ = row.Dot(v)
	}

	return res, nil
}

// MulXMatY calculates the function x^T * m * y, where x and y are
// vectors.
func (m Matrix) MulXMatY(x, y Vector) (*big.Int, error) {
	t, err := m.MulVec(y)
	if err != nil {
		return nil, err
	}
	v, err := t.Dot(x)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// Minor returns a matrix obtained from m by removing row i and column j.
// It returns an error if i >= number of rows of m, or if j >= number of
// columns of m.
func (m Matrix) Minor(i int, j int) (Matrix, error) {
	if i >= m.Rows() || j >= m.Cols() {
		return nil, fmt.Errorf("cannot obtain minor - out of bounds")
	}
	mat := make(Matrix, m.Rows()-1)
	for k := 0; k < m.Rows(); k++ {
		if k == i {
			continue
		}
		vec := make(Vector, 0, len(m[0])-1)
		vec = append(vec, m[k][:j]...)
		vec = append(vec, m[k][j+1:]...)
		if k < i {
			mat[k] = vec
		} else {
			mat[k-1] = vec
		}
	}

	return NewMatrix(mat)
}

// Determinant returns the determinant of matrix m.
// It returns an error if the determinant does not exist.
func (m Matrix) Determinant() (*big.Int, error) {
	if m.Rows() == 1 {
		return new(big.Int).Set(m[0][0]), nil
	}
	det := big.NewInt(0)
	sign := big.NewInt(1)
	for i := 0; i < m.Rows(); i++ {
		minor, err := m.Minor(0, i)
		if err != nil {
			return nil, err
		}
		value, err := minor.Determinant()
		if err != nil {
			return nil, err
		}
		value.Mul(value, m[0][i])
		value.Mul(value, sign)
		sign.Neg(sign)
		det.Add(det, value)
	}

	return det, nil
}

// InverseMod returns the inverse matrix of m in the group Z_p.
// Note that as we consider only matrix with integers,
// the inverse exists only in Z_p.
//
// It returns an error in case matrix is not invertible.
func (m Matrix) InverseMod(p *big.Int) (Matrix, error) {
	mat := make(Matrix, m.Rows())
	det, err := m.Determinant()
	if err != nil {
		return nil, err
	}
	det.Mod(det, p)
	if det.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("matrix non-invertable")
	}
	invDet := new(big.Int).ModInverse(det, p)
	sign := new(big.Int)
	minusOne := big.NewInt(-1)
	for i := 0; i < m.Rows(); i++ {
		row := make(Vector, m.Cols())
		for j := 0; j < m.Cols(); j++ {
			minor, err := m.Minor(i, j)
			if err != nil {
				return nil, err
			}
			value, err := minor.Determinant()
			if err != nil {
				return nil, err
			}
			value.Mod(value, p)
			sign.Exp(minusOne, big.NewInt(int64(i+j)), nil)
			value.Mul(value, sign)
			value.Mul(value, invDet)
			value.Mod(value, p)
			row[j] = value
		}
		mat[i] = row
	}
	co, err := NewMatrix(mat)
	if err != nil {
		return nil, err
	}

	return co.Transpose(), nil
}

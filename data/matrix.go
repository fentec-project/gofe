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

	"github.com/fentec-project/bn256"
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

// NewRandomDetMatrix returns a new Matrix instance
// with random elements sampled by a pseudo-random
// number generator. Elements are sampled from [0, max) and key
// determines the pseudo-random generator.
func NewRandomDetMatrix(rows, cols int, max *big.Int, key *[32]byte) (Matrix, error) {
	l := rows * cols
	v, err := NewRandomDetVector(l, max, key)
	if err != nil {
		return nil, err
	}

	mat := make([]Vector, rows)
	for i := 0; i < rows; i++ {
		mat[i] = NewVector(v[(i * cols):((i + 1) * cols)])
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

// Dot calculates the dot product (inner product) of matrices m and other,
// which we define as the sum of the dot product of rows of both matrices.
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

	prod := make([]Vector, m.Rows())
	for i := 0; i < m.Rows(); i++ {
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
	if m.Rows() == 1 {
		mat[0] = Vector{invDet}
		return mat, nil
	}
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

// MulG1 calculates m * [bn256.G1] and returns the
// result in a new MatrixG1 instance.
func (m Matrix) MulG1() MatrixG1 {
	prod := make(MatrixG1, len(m))
	for i := range prod {
		prod[i] = m[i].MulG1()
	}

	return prod
}

// MulG2 calculates m * [bn256.G1] and returns the
// result in a new MatrixG2 instance.
func (m Matrix) MulG2() MatrixG2 {
	prod := make(MatrixG2, len(m))
	for i := range prod {
		prod[i] = m[i].MulG2()
	}

	return prod
}

// MatMulMatG1 multiplies m and other in the sense that
// if other is t * [bn256.G1] for some matrix t, then the
// function returns m * t * [bn256.G1] where m * t is a
// matrix multiplication.
func (m Matrix) MatMulMatG1(other MatrixG1) (MatrixG1, error) {
	if m.Cols() != other.Rows() {
		return nil, fmt.Errorf("cannot multiply matrices")
	}

	prod := make(MatrixG1, m.Rows())
	for i := 0; i < m.Rows(); i++ {
		prod[i] = make([]*bn256.G1, other.Cols())
		for j := 0; j < other.Cols(); j++ {
			prod[i][j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
			for k := 0; k < m.Cols(); k++ {
				mik := new(big.Int).Set(m[i][k])
				okj := new(bn256.G1).Set(other[k][j])
				if m[i][k].Sign() == -1 {
					okj.Neg(okj)
					mik.Neg(mik)
				}
				tmp := new(bn256.G1).ScalarMult(okj, mik)
				prod[i][j].Add(tmp, prod[i][j])
			}
		}
	}

	return prod, nil
}

// MatMulMatG2 multiplies m and other in the sense that
// if other is t * [bn256.G2] for some matrix t, then the
// function returns m * t * [bn256.G2] where m * t is a
// matrix multiplication.
func (m Matrix) MatMulMatG2(other MatrixG2) (MatrixG2, error) {
	if m.Cols() != other.Rows() {
		return nil, fmt.Errorf("cannot multiply matrices")
	}

	prod := make(MatrixG2, m.Rows())
	for i := 0; i < m.Rows(); i++ {
		prod[i] = make([]*bn256.G2, other.Cols())
		for j := 0; j < other.Cols(); j++ {
			prod[i][j] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
			for k := 0; k < m.Cols(); k++ {
				mik := new(big.Int).Set(m[i][k])
				okj := new(bn256.G2).Set(other[k][j])
				if m[i][k].Sign() == -1 {
					okj.Neg(okj)
					mik.Neg(mik)
				}
				tmp := new(bn256.G2).ScalarMult(okj, mik)
				prod[i][j].Add(tmp, prod[i][j])
			}
		}
	}

	return prod, nil
}

// MatMulVecG2 multiplies m and other in the sense that
// if other is t * [bn256.G2] for some vector t, then the
// function returns m * t * [bn256.G2] where m * t is a
// matrix-vector multiplication.
func (m Matrix) MatMulVecG2(other VectorG2) (VectorG2, error) {
	if m.Cols() != len(other) {
		return nil, fmt.Errorf("dimensions don't fit")
	}

	prod := make(VectorG2, m.Rows())
	for j := 0; j < m.Rows(); j++ {
		prod[j] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
		for k := 0; k < m.Cols(); k++ {
			mjk := new(big.Int).Set(m[j][k])
			ok := new(bn256.G2).Set(other[k])
			if m[j][k].Sign() == -1 {
				ok.Neg(ok)
				mjk.Neg(mjk)
			}
			tmp := new(bn256.G2).ScalarMult(ok, mjk)
			prod[j].Add(tmp, prod[j])
		}
	}

	return prod, nil
}

// GaussianElimination uses Gaussian elimination to transform a matrix
// into an equivalent upper triangular form
func (m Matrix) GaussianElimination(p *big.Int) (Matrix, error) {
	if m.Rows() == 0 || m.Cols() == 0 {
		return nil, fmt.Errorf("the matrix should not be empty")
	}

	// we copy matrix m into res and v into u
	res := make(Matrix, m.Rows())
	for i := 0; i < m.Rows(); i++ {
		res[i] = make(Vector, m.Cols())
		for j := 0; j < m.Cols(); j++ {
			res[i][j] = new(big.Int).Set(m[i][j])
		}
	}

	// res and u are transformed to be in the upper triangular form
	h, k := 0, 0
	for h < m.Rows() && k < res.Cols() {
		zero := true
		for i := h; i < m.Rows(); i++ {
			if res[i][k].Sign() != 0 {
				res[h], res[i] = res[i], res[h]
				zero = false
				break
			}
		}
		if zero {
			k++
			continue
		}
		mHKInv := new(big.Int).ModInverse(res[h][k], p)
		for i := h + 1; i < m.Rows(); i++ {
			f := new(big.Int).Mul(mHKInv, res[i][k])
			res[i][k] = big.NewInt(0)
			for j := k + 1; j < res.Cols(); j++ {
				res[i][j].Sub(res[i][j], new(big.Int).Mul(f, res[h][j]))
				res[i][j].Mod(res[i][j], p)
			}
		}
		k++
		h++
	}

	return res, nil
}

// InverseModGauss returns the inverse matrix of m in the group Z_p.
// The algorithm uses Gaussian elimination. It returns the determinant
// as well. In case the matrix is not invertible it returns an error.
func (m Matrix) InverseModGauss(p *big.Int) (Matrix, *big.Int, error) {
	if m.Rows() == 0 || m.Cols() == 0 {
		return nil, nil, fmt.Errorf("the matrix should not be empty")
	}
	if m.Rows() != m.Cols() {
		return nil, nil, fmt.Errorf("the number of rows must equal the number of columns")
	}

	// we copy matrix m into matExt and extend it with identity
	matExt := make(Matrix, m.Rows())
	for i := 0; i < m.Rows(); i++ {
		matExt[i] = make(Vector, m.Cols()*2)
		for j := 0; j < m.Cols(); j++ {
			matExt[i][j] = new(big.Int).Set(m[i][j])
		}
		for j := m.Cols(); j < 2*m.Cols(); j++ {
			if i+m.Cols() == j {
				matExt[i][j] = big.NewInt(1)
			} else {
				matExt[i][j] = big.NewInt(0)
			}

		}
	}

	triang, err := matExt.GaussianElimination(p)
	if err != nil {
		return nil, nil, err
	}

	// check if the inverse can be computed
	det := big.NewInt(1)
	for i := 0; i < matExt.Rows(); i++ {
		det.Mul(det, triang[i][i])
		det.Mod(det, p)
	}
	if det.Sign() == 0 {
		return nil, det, fmt.Errorf("matrix non-invertable")
	}

	// use the upper triangular form to obtain the solution
	matInv := make(Matrix, m.Rows())
	for k := 0; k < m.Rows(); k++ {
		matInv[k] = make(Vector, m.Cols())
		for i := m.Rows() - 1; i >= 0; i-- {
			for j := m.Rows() - 1; j >= 0; j-- {
				if matInv[k][j] == nil {
					tmpSum, _ := triang[i][j+1 : m.Cols()].Dot(matInv[k][j+1:])
					matInv[k][j] = new(big.Int).Sub(triang[i][m.Cols()+k], tmpSum)
					mHKInv := new(big.Int).ModInverse(triang[i][j], p)
					matInv[k][j].Mul(matInv[k][j], mHKInv)
					matInv[k][j].Mod(matInv[k][j], p)
					break
				}
			}
		}
	}

	return matInv.Transpose(), det, nil
}

// DeterminantGauss returns the determinant of matrix m using Gaussian
// elimination. It returns an error if the determinant does not exist.
func (m Matrix) DeterminantGauss(p *big.Int) (*big.Int, error) {
	if m.Rows() != m.Cols() {
		return nil, fmt.Errorf("number of rows must equal number of columns")
	}
	triang, err := m.GaussianElimination(p)
	if err != nil {
		return nil, err
	}

	ret := big.NewInt(1)
	for i := 0; i < m.Cols(); i++ {
		ret.Mul(ret, triang[i][i])
		ret.Mod(ret, p)
	}

	return ret, nil
}

// GaussianEliminationSolver solves a vector equation mat * x = v and finds vector x,
// using Gaussian elimination. Arithmetic operations are considered to be over
// Z_p, where p should be a prime number. If such x does not exist, then the
// function returns an error.
func GaussianEliminationSolver(mat Matrix, v Vector, p *big.Int) (Vector, error) {
	if mat.Rows() == 0 || mat.Cols() == 0 {
		return nil, fmt.Errorf("the matrix should not be empty")
	}
	if mat.Rows() != len(v) {
		return nil, fmt.Errorf(fmt.Sprintf("dimensions should match: "+
			"rows of the matrix %d, length of the vector %d", mat.Rows(), len(v)))
	}

	// we copy matrix mat into m and v into u
	cpMat := make([]Vector, mat.Rows())
	u := make(Vector, mat.Rows())
	for i := 0; i < mat.Rows(); i++ {
		cpMat[i] = make(Vector, mat.Cols())
		for j := 0; j < mat.Cols(); j++ {
			cpMat[i][j] = new(big.Int).Set(mat[i][j])
		}
		u[i] = new(big.Int).Set(v[i])
	}
	m, _ := NewMatrix(cpMat) // error is impossible to happen

	// m and u are transformed to be in the upper triangular form
	ret := make(Vector, mat.Cols())
	h, k := 0, 0
	for h < mat.Rows() && k < mat.Cols() {
		zero := true
		for i := h; i < mat.Rows(); i++ {
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
		for i := h + 1; i < mat.Rows(); i++ {
			f := new(big.Int).Mul(mHKInv, m[i][k])
			m[i][k] = big.NewInt(0)
			for j := k + 1; j < mat.Cols(); j++ {
				m[i][j].Sub(m[i][j], new(big.Int).Mul(f, m[h][j]))
				m[i][j].Mod(m[i][j], p)
			}
			u[i].Sub(u[i], new(big.Int).Mul(f, u[h]))
			u[i].Mod(u[i], p)
		}
		k++
		h++
	}

	for i := h; i < mat.Rows(); i++ {
		if u[i].Sign() != 0 {
			return nil, fmt.Errorf("no solution")
		}
	}
	for j := k; j < mat.Cols(); j++ {
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

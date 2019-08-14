package data

import (
	"fmt"
	"github.com/fentec-project/bn256"
	"math/big"
)

// Matrix wraps a slice of VectorG1 elements. It represents a row-major.
// order matrix.
//
// The j-th element from the i-th vector of the matrix can be obtained
// as m[i][j].
type MatrixG1 []VectorG1

// Rows returns the number of rows of matrixG1 m.
func (m MatrixG1) Rows() int {
	return len(m)
}

// Cols returns the number of columns of matrixG1 m.
func (m MatrixG1) Cols() int {
	if len(m) != 0 {
		return len(m[0])
	}

	return 0
}

// GetCol returns i-th column of matrix m as a vector.
// It returns error if i >= the number of m's columns.
func (m MatrixG1) GetCol(i int) (VectorG1, error) {
	if i >= m.Cols() {
		return nil, fmt.Errorf("column index exceeds matrix dimensions")
	}

	column := make([]*bn256.G1, m.Rows())
	for j := 0; j < m.Rows(); j++ {
		column[j] = m[j][i]
	}

	return VectorG1(column), nil
}

// Transpose transposes matrix m and returns
// the result in a new Matrix.
func (m MatrixG1) Transpose() MatrixG1 {
	transposed := make([]VectorG1, m.Cols())
	for i := 0; i < m.Cols(); i++ {
		transposed[i], _ = m.GetCol(i)
	}

	return MatrixG1(transposed)
}

// Add sums vectors v1 and v2 (also v1 * v2 in multiplicative notation).
// It returns the result in a new VectorG1 instance.
func (v MatrixG1) Add(other MatrixG1) MatrixG1 {
	sum := make(MatrixG1, len(v))
	for i := range sum {
		sum[i] = v[i].Add(other[i])
	}

	return sum
}

// MulScalar multiplies matrix m by a scalar s
func (m MatrixG1) MulScalar(s *big.Int) MatrixG1 {
	out := make([]VectorG1, m.Rows())
	for i := range out {
		out[i] = m[i].MulScalar(s)
	}

	return MatrixG1(out)
}

// MulVector multiplies matrix m by a vector v, i.e if
// m is t * [bn256.G1] for some matrix t, then the result
// is (t * v) [bn256.G1]
func (m MatrixG1) MulVector(v Vector) VectorG1 {
	out := make(VectorG1, m.Rows())
	for i := range out {
		out[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		for k := 0; k < m.Cols(); k++ {
			tmp := new(bn256.G1).ScalarMult(m[i][k], v[k])
			out[i].Add(out[i], tmp)
		}
	}

	return out
}

// Matrix wraps a slice of VectorG2 elements. It represents a row-major.
// order matrix.
//
// The j-th element from the i-th vector of the matrix can be obtained
// as m[i][j].
type MatrixG2 []VectorG2

// Rows returns the number of rows of matrixG2 m.
func (m MatrixG2) Rows() int {
	return len(m)
}
// Cols returns the number of columns of matrixG2 m.
func (m MatrixG2) Cols() int {
	if len(m) != 0 {
		return len(m[0])
	}

	return 0
}
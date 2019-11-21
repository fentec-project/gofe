package data

import (
	"math/big"

	"github.com/fentec-project/bn256"
)

// MatrixG1 wraps a slice of VectorG1 elements. It represents a row-major.
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

// Add sums matrices m and other componentwise.
// It returns the result in a new MatrixG1 instance.
func (m MatrixG1) Add(other MatrixG1) MatrixG1 {
	sum := make(MatrixG1, len(m))
	for i := range sum {
		sum[i] = m[i].Add(other[i])
	}

	return sum
}

// MulScalar multiplies matrix m by a scalar s.
// It returns the result in a new MatrixG1 instance.
func (m MatrixG1) MulScalar(s *big.Int) MatrixG1 {
	out := make(MatrixG1, m.Rows())
	for i := range out {
		out[i] = m[i].MulScalar(s)
	}

	return out
}

// MulVector multiplies matrix m by a vector v, i.e if
// m is t * [bn256.G1] for some matrix t, then the result
// is (t * v) [bn256.G1]
func (m MatrixG1) MulVector(v Vector) VectorG1 {
	out := make(VectorG1, m.Rows())
	for i := range out {
		out[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		for k := 0; k < m.Cols(); k++ {
			mik := new(bn256.G1).Set(m[i][k])
			vk := new(big.Int).Set(v[k])
			if v[k].Sign() == -1 {
				vk.Neg(vk)
				mik.Neg(mik)
			}
			tmp := new(bn256.G1).ScalarMult(mik, vk)
			out[i].Add(tmp, out[i])
		}
	}

	return out
}

// MatrixG2 wraps a slice of VectorG2 elements. It represents a row-major.
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

// MulScalar multiplies matrix m by a scalar s
func (m MatrixG2) MulScalar(s *big.Int) MatrixG2 {
	out := make(MatrixG2, m.Rows())
	for i := range out {
		out[i] = m[i].MulScalar(s)
	}

	return out
}

// MulVector multiplies matrix m by a vector v, i.e if
// m is t * [bn256.G2] for some matrix t, then the result
// is (t * v) [bn256.G2]
func (m MatrixG2) MulVector(v Vector) VectorG2 {
	out := make(VectorG2, m.Rows())
	for i := range out {
		out[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
		for k := 0; k < m.Cols(); k++ {
			mik := new(bn256.G2).Set(m[i][k])
			vk := new(big.Int).Set(v[k])
			if v[k].Sign() == -1 {
				vk.Neg(vk)
				mik.Neg(mik)
			}
			tmp := new(bn256.G2).ScalarMult(mik, vk)
			out[i].Add(tmp, out[i])
		}
	}

	return out
}

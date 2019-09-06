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
	"golang.org/x/crypto/salsa20"
)

// Vector wraps a slice of *big.Int elements.
type Vector []*big.Int

// NewVector returns a new Vector instance.
func NewVector(coordinates []*big.Int) Vector {
	return Vector(coordinates)
}

// NewRandomVector returns a new Vector instance
// with random elements sampled by the provided sample.Sampler.
// Returns an error in case of sampling failure.
func NewRandomVector(len int, sampler sample.Sampler) (Vector, error) {
	vec := make([]*big.Int, len)
	var err error

	for i := 0; i < len; i++ {
		vec[i], err = sampler.Sample()
		if err != nil {
			return nil, err
		}
	}

	return NewVector(vec), nil
}

// NewRandomDetVector returns a new Vector instance
// with (deterministic) random elements sampled by a pseudo-random
// number generator. Elements are sampled from [0, max) and key
// determines the pseudo-random generator.
func NewRandomDetVector(len int, max *big.Int, key *[32]byte) (Vector, error) {
	if max.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("upper bound on samples should be at least 2")
	}

	maxBits := new(big.Int).Sub(max, big.NewInt(1)).BitLen()
	maxBytes := (maxBits + 7) / 8
	over := uint((8 * maxBytes) - maxBits)

	lTimesMaxBytes := len * maxBytes
	nonce := make([]byte, 8) // nonce is initialized to zeros
	ret := make([]*big.Int, len)

	for i := 3; true; i++ {
		in := make([]byte, i*lTimesMaxBytes) // input is initialized to zeros

		out := make([]byte, i*lTimesMaxBytes)

		salsa20.XORKeyStream(out, in, nonce, key)

		j := 0
		k := 0
		for j < (i * lTimesMaxBytes) {
			out[j] = out[j] >> over
			ret[k] = new(big.Int).SetBytes(out[j:(j + maxBytes)])
			if ret[k].Cmp(max) < 0 {
				k++
			}
			if k == len {
				break
			}
			j += maxBytes

		}
		if k == len {
			break
		}
	}

	return NewVector(ret), nil
}

// NewConstantVector returns a new Vector instance
// with all elements set to constant c.
func NewConstantVector(len int, c *big.Int) Vector {
	vec := make([]*big.Int, len)
	for i := 0; i < len; i++ {
		vec[i] = new(big.Int).Set(c)
	}

	return vec
}

// Copy creates a new vector with the same values
// of the entries.
func (v Vector) Copy() Vector {
	newVec := make(Vector, len(v))

	for i, c := range v {
		newVec[i] = new(big.Int).Set(c)
	}

	return newVec
}

// MulScalar multiplies vector v by a given scalar x.
// The result is returned in a new Vector.
func (v Vector) MulScalar(x *big.Int) Vector {
	res := make(Vector, len(v))
	for i, vi := range v {
		res[i] = new(big.Int).Mul(x, vi)
	}

	return res
}

// Mod performs modulo operation on vector's elements.
// The result is returned in a new Vector.
func (v Vector) Mod(modulo *big.Int) Vector {
	newCoords := make([]*big.Int, len(v))

	for i, c := range v {
		newCoords[i] = new(big.Int).Mod(c, modulo)
	}

	return NewVector(newCoords)
}

// CheckBound checks whether the absolute values of all vector elements
// are strictly smaller than the provided bound.
// It returns error if at least one element's absolute value is >= bound.
func (v Vector) CheckBound(bound *big.Int) error {
	abs := new(big.Int)
	for _, c := range v {
		abs.Abs(c)
		if abs.Cmp(bound) > -1 {
			return fmt.Errorf("all coordinates of a vector should be smaller than bound")
		}
	}

	return nil
}

// Apply applies an element-wise function f to vector v.
// The result is returned in a new Vector.
func (v Vector) Apply(f func(*big.Int) *big.Int) Vector {
	res := make(Vector, len(v))

	for i, vi := range v {
		res[i] = f(vi)
	}

	return res
}

// Add adds vectors v and other.
// The result is returned in a new Vector.
func (v Vector) Add(other Vector) Vector {
	sum := make([]*big.Int, len(v))

	for i, c := range v {
		sum[i] = new(big.Int).Add(c, other[i])
	}

	return NewVector(sum)
}

// Sub subtracts vectors v and other.
// The result is returned in a new Vector.
func (v Vector) Sub(other Vector) Vector {
	sub := make([]*big.Int, len(v))
	for i, c := range v {
		sub[i] = new(big.Int).Sub(c, other[i])
	}

	return sub
}

// Dot calculates the dot product (inner product) of vectors v and other.
// It returns an error if vectors have different numbers of elements.
func (v Vector) Dot(other Vector) (*big.Int, error) {
	prod := big.NewInt(0)

	if len(v) != len(other) {
		return nil, fmt.Errorf("vectors should be of same length")
	}

	for i, c := range v {
		prod = prod.Add(prod, new(big.Int).Mul(c, other[i]))
	}

	return prod, nil
}

// MulAsPolyInRing multiplies vectors v and other as polynomials
// in the ring of polynomials R = Z[x]/((x^n)+1), where n is length of
// the vectors. Note that the input vector [1, 2, 3] represents a
// polynomial Z[x] = x²+2x+3.
// It returns a new polynomial with degree <= n-1.
//
// If vectors differ in size, error is returned.
func (v Vector) MulAsPolyInRing(other Vector) (Vector, error) {
	if len(v) != len(other) {
		return nil, fmt.Errorf("vectors must have the same length")
	}
	n := len(v)

	// Result will be a polynomial with the degree <= n-1
	prod := new(big.Int)
	res := make(Vector, n)

	// Over all degrees, beginning at lowest degree
	for i := 0; i < n; i++ {
		res[i] = big.NewInt(0)
		// Handle products with degrees < n
		for j := 0; j <= i; j++ {
			prod.Mul(v[i-j], other[j]) // Multiply coefficients
			res[i].Add(res[i], prod)
		}
		// Handle products with degrees >= n
		for j := i + 1; j < n; j++ {
			prod.Mul(v[n+i-j], other[j]) // Multiply coefficients
			prod.Neg(prod)               // Negate, because x^n = -1
			res[i].Add(res[i], prod)
		}
	}

	return res, nil
}

// MulG1 calculates bn256.G1 * v (also g1^v in multiplicative notation)
// and returns the result (v[0] * bn256.G1, ... , v[n-1] * bn256.G1) in a
// VectorG1 instance.
func (v Vector) MulG1() VectorG1 {
	prod := make(VectorG1, len(v))
	for i := range prod {
		prod[i] = new(bn256.G1).ScalarBaseMult(v[i])
	}

	return prod
}

// MulVecG1 calculates g1 * v (also g1^v in multiplicative notation)
// and returns the result (v[0] * g1[0], ... , v[n-1] * g1[n-1]) in a
// VectorG1 instance.
func (v Vector) MulVecG1(g1 VectorG1) VectorG1 {
	zero := big.NewInt(0)

	prod := make(VectorG1, len(v))
	for i := range prod {
		vi := new(big.Int).Set(v[i])
		g1i := new(bn256.G1).Set(g1[i])
		if vi.Cmp(zero) == -1 {
			g1i.Neg(g1i)
			vi.Neg(vi)
		}
		prod[i] = new(bn256.G1).ScalarMult(g1i, vi)
	}

	return prod
}

// MulG2 calculates bn256.G2 * v (also g2^v in multiplicative notation)
// and returns the result (v[0] * bn256.G2, ... , v[n-1] * bn256.G2) in a
// VectorG2 instance.
func (v Vector) MulG2() VectorG2 {
	prod := make(VectorG2, len(v))
	for i := range prod {
		prod[i] = new(bn256.G2).ScalarBaseMult(v[i])
	}

	return prod
}

// MulVecG2 calculates g2 * v (also g2^v in multiplicative notation)
// and returns the result (v[0] * g2[0], ... , v[n-1] * g2[n-1]) in a
// VectorG2 instance.
func (v Vector) MulVecG2(g2 VectorG2) VectorG2 {
	zero := big.NewInt(0)

	prod := make(VectorG2, len(v))
	for i := range prod {
		vi := new(big.Int).Set(v[i])
		g2i := new(bn256.G2).Set(g2[i])
		if vi.Cmp(zero) == -1 {
			g2i.Neg(g2i)
			vi.Neg(vi)
		}
		prod[i] = new(bn256.G2).ScalarMult(g2i, vi)
	}

	return prod
}

// String produces a string representation of a vector.
func (v Vector) String() string {
	vStr := ""
	for _, yi := range v {
		vStr = vStr + " " + yi.String()
	}
	return vStr
}

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
	"math/big"

	"github.com/fentec-project/bn256"
)

// VectorG1 wraps a slice of elements from elliptic curve BN256.G1 group.
type VectorG1 []*bn256.G1

// Add sums vectors v1 and v2 (also v1 * v2 in multiplicative notation).
// It returns the result in a new VectorG1 instance.
func (v VectorG1) Add(other VectorG1) VectorG1 {
	sum := make(VectorG1, len(v))
	for i := range sum {
		sum[i] = new(bn256.G1).Add(v[i], other[i])
	}

	return sum
}

// Neg returns a new VectorG1 instance with
// values -v in the additive notation.
func (v VectorG1) Neg() VectorG1 {
	neg := make(VectorG1, len(v))
	for i := range neg {
		neg[i] = new(bn256.G1).Neg(v[i])
	}

	return neg
}

// Copy produces a new copy of vector v.
func (v VectorG1) Copy() VectorG1 {
	cp := make(VectorG1, len(v))
	for i := range cp {
		cp[i] = new(bn256.G1).Set(v[i])
	}

	return cp
}

// MulScalar multiplies s * v (in additive notation).
func (v VectorG1) MulScalar(s *big.Int) VectorG1 {
	sTmp := new(big.Int).Set(s)
	out := v.Copy()
	if s.Sign() == -1 {
		sTmp.Neg(s)
		out = out.Neg()
	}

	for i := range out {
		out[i].ScalarMult(out[i], sTmp)
	}

	return out
}

// VectorG2 wraps a slice of elements from elliptic curve BN256.G2 group.
type VectorG2 []*bn256.G2

// Add sums vectors v1 and v2 (also v1 * v2 in multiplicative notation).
// It returns the result in a new VectorG2 instance.
func (v VectorG2) Add(other VectorG2) VectorG2 {
	sum := make(VectorG2, len(v))
	for i := range sum {
		sum[i] = new(bn256.G2).Add(v[i], other[i])
	}

	return sum
}

// Neg returns a new VectorG1 instance with
// values -v in the additive notation.
func (v VectorG2) Neg() VectorG2 {
	neg := make(VectorG2, len(v))
	for i := range neg {
		neg[i] = new(bn256.G2).Neg(v[i])
	}

	return neg
}

// Copy produces a new copy of vector v.
func (v VectorG2) Copy() VectorG2 {
	cp := make(VectorG2, len(v))
	for i := range cp {
		cp[i] = new(bn256.G2).Set(v[i])
	}

	return cp
}

// MulScalar multiplies s * v (in additive notation).
func (v VectorG2) MulScalar(s *big.Int) VectorG2 {
	sTmp := new(big.Int).Set(s)
	out := v.Copy()
	if s.Sign() == -1 {
		sTmp.Neg(s)
		out = out.Neg()
	}

	for i := range out {
		out[i].ScalarMult(out[i], sTmp)
	}

	return out
}

// VectorGT wraps a slice of elements from pairing BN256.GT group.
type VectorGT []*bn256.GT

// Dot multiplies v = (v_1,...,v_n) and other = (o_1,...,o_n) to
// return v1 * o_1 + ... + v_n *o_n (in additive notation)
func (v VectorGT) Dot(other Vector) *bn256.GT {
	prod := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	for i, c := range v {
		prod.Add(prod, new(bn256.GT).ScalarMult(c, other[i]))
	}

	return prod
}

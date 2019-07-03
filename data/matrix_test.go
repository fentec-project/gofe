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
	"testing"

	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestMatrix(t *testing.T) {
	rows, cols := 5, 3
	bound := new(big.Int).Exp(big.NewInt(2), big.NewInt(20), big.NewInt(0))
	sampler := sample.NewUniform(bound)

	x, err := NewRandomMatrix(rows, cols, sampler)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	y, err := NewRandomMatrix(rows, cols, sampler)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	add, err := x.Add(y)

	if err != nil {
		t.Fatalf("Error during matrix addition: %v", err)
	}

	modulo := big.NewInt(int64(104729))
	mod := x.Mod(modulo)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			assert.Equal(t, new(big.Int).Add(x[i][j], y[i][j]), add[i][j], "coordinates should sum correctly")
			assert.Equal(t, new(big.Int).Mod(x[i][j], modulo), mod[i][j], "coordinates should mod correctly")
		}
	}

	sampler = sample.NewUniform(big.NewInt(256))
	var key [32]byte
	for i := range key {
		r, _ := sampler.Sample()
		key[i] = byte(r.Int64())
	}

	_, err = NewRandomDetMatrix(100, 100, big.NewInt(5), &key)
	assert.Equal(t, err, nil)
}

func TestMatrix_Rows(t *testing.T) {
	m, _ := NewRandomMatrix(2, 3, sample.NewUniform(big.NewInt(10)))
	assert.Equal(t, 2, m.Rows())
}

func TestMatrix_Cols(t *testing.T) {
	m, _ := NewRandomMatrix(2, 3, sample.NewUniform(big.NewInt(10)))
	assert.Equal(t, 3, m.Cols())
}

func TestMatrix_Empty(t *testing.T) {
	var m Matrix
	assert.Equal(t, 0, m.Rows())
	assert.Equal(t, 0, m.Cols())
}

func TestMatrix_DimsMatch(t *testing.T) {
	sampler := sample.NewUniform(big.NewInt(10))
	m1, _ := NewRandomMatrix(2, 3, sampler)
	m2, _ := NewRandomMatrix(2, 3, sampler)
	m3, _ := NewRandomMatrix(2, 4, sampler)
	m4, _ := NewRandomMatrix(3, 3, sampler)

	assert.True(t, m1.DimsMatch(m2))
	assert.False(t, m1.DimsMatch(m3))
	assert.False(t, m1.DimsMatch(m4))
}

func TestMatrix_CheckDims(t *testing.T) {
	sampler := sample.NewUniform(big.NewInt(10))
	m, _ := NewRandomMatrix(2, 2, sampler)

	assert.True(t, m.CheckDims(2, 2))
	assert.False(t, m.CheckDims(2, 3))
	assert.False(t, m.CheckDims(3, 2))
	assert.False(t, m.CheckDims(3, 3))
}

func TestMatrix_Dot(t *testing.T) {
	m1 := Matrix{
		Vector{big.NewInt(1), big.NewInt(2)},
		Vector{big.NewInt(3), big.NewInt(4)},
	}
	m2 := Matrix{
		Vector{big.NewInt(4), big.NewInt(3)},
		Vector{big.NewInt(2), big.NewInt(1)},
	}
	mismatched := Matrix{
		Vector{big.NewInt(1), big.NewInt(2)},
	}

	dot, _ := m1.Dot(m2)
	_, err := m1.Dot(mismatched)

	assert.Equal(t, big.NewInt(20), dot, "dot product of matrices does not work correctly")
	assert.Error(t, err, "expected an error to because of dimension mismatch")
}

func TestMatrix_MulScalar(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	m := Matrix{
		Vector{one, one, one},
		Vector{one, one, one},
	}
	mTimesTwo := Matrix{
		Vector{two, two, two},
		Vector{two, two, two},
	}

	assert.Equal(t, m.MulScalar(two), mTimesTwo)
}

func TestMatrix_MulVec(t *testing.T) {
	m := Matrix{
		Vector{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
		Vector{big.NewInt(4), big.NewInt(5), big.NewInt(6)},
	}
	v := Vector{big.NewInt(2), big.NewInt(2), big.NewInt(2)}
	vMismatched := Vector{big.NewInt(1)}

	mvExpected := Vector{big.NewInt(12), big.NewInt(30)}
	mv, _ := m.MulVec(v)
	_, err := m.MulVec(vMismatched)

	assert.Equal(t, mvExpected, mv, "product of matrix and vector does not work correctly")
	assert.Error(t, err, "expected an error to because of dimension mismatch")
}

func TestMatrix_Mul(t *testing.T) {
	m1 := Matrix{
		Vector{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
		Vector{big.NewInt(4), big.NewInt(5), big.NewInt(6)},
	}
	m2 := Matrix{
		Vector{big.NewInt(1), big.NewInt(2)},
		Vector{big.NewInt(3), big.NewInt(4)},
		Vector{big.NewInt(5), big.NewInt(6)},
	}
	mismatched := Matrix{Vector{big.NewInt(1)}}

	prodExpected := Matrix{
		Vector{big.NewInt(22), big.NewInt(28)},
		Vector{big.NewInt(49), big.NewInt(64)},
	}
	prod, _ := m1.Mul(m2)
	_, err := m1.Mul(mismatched)

	assert.Equal(t, prodExpected, prod, "product of matrices does not work correctly")
	assert.Error(t, err, "expected an error to because of dimension mismatch")
}

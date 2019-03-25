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
	"github.com/fentec-project/bn256"
)

// VectorG1 wraps a slice of elements from elliptic curve BN256.G1 group.
type VectorG1 []*bn256.G1

// TODO add error handling

// Add sums vectors v1 and v2 (also v1 * v2 in multiplicative notation).
// It returns the result in a new VectorG1 instance.
func (v VectorG1) Add(other VectorG1) VectorG1 {
	sum := make(VectorG1, len(v))
	for i := range sum {
		sum[i] = new(bn256.G1).Add(v[i], other[i])
	}

	return sum
}

// VectorG2 wraps a slice of elements from elliptic curve BN256.G2 group.
type VectorG2 []*bn256.G2

// TODO add error handling

// Add sums vectors v1 and v2 (also v1 * v2 in multiplicative notation).
// It returns the result in a new VectorG2 instance.
func (v VectorG2) Add(other VectorG2) VectorG2 {
	sum := make(VectorG2, len(v))
	for i := range sum {
		sum[i] = new(bn256.G2).Add(v[i], other[i])
	}

	return sum
}

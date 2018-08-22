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

package sample

import (
	"math/big"
	"math/rand"
	"sort"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
type NormalCumulative struct {
	*Normal
	precomputed []float64
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalCumulative(sigma, eps, k float64) *NormalCumulative {
	s := &NormalCumulative{
		Normal:      NewNormal(sigma, eps, k),
		precomputed: nil,
	}

	s.precompute()

	return s
}

// Sample samples discrete cumulative distribution with
// precomputed values.
// TODO: Currently this is limited with the precison of float64 type.
func (c *NormalCumulative) Sample() (*big.Int, error) {
	eps := int(c.eps)
	sample := float64(rand.Intn(2*eps) % eps)
	sample *= c.precomputed[c.cut]
	sample /= c.eps

	sign := 2*int(sample)/eps - 1 // should be -1 or 1

	// Find the precomputed sample
	i := sort.SearchFloat64s(c.precomputed, sample)
	res := big.NewInt(int64(sign) * int64(c.precomputed[i]))

	return res, nil
}

// precompute precomputes the values for sampling.
// TODO: Currently this is limited with the precison of float64 type.
func (c *NormalCumulative) precompute() {
	t := make([]float64, c.cut+1) // t is table of precomputed values
	t[0] = 0
	for i := 1; i <= c.cut; i++ {
		t[i] = t[i-1] + c.density(float64(i))
	}

	c.precomputed = t
}

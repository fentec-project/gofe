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
	"crypto/rand"
	"math"
	"math/big"
	"sort"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
// This sampler is the fastest, but is limited only to cases when sigma
// is not too big, due to the sizes of the precomputed tables. Note that
// the sampler offers arbitrary precision but the implementation is not
// constant time.
type NormalCumulative struct {
	*normal
	// table of precomputed values relative to the cumulative distribution
	precomputed []*big.Int
	// twoSided defines if we limit sampling only to non-negative integers
	// or to all
	twoSided bool
	// integer defining from how big of an interval do we need to sample
	// uniformly to sample according to discrete Gauss
	sampleSize *big.Int
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalCumulative(sigma *big.Float, n uint, twoSided bool) *NormalCumulative {
	s := &NormalCumulative{
		normal:   newNormal(sigma, n),
		twoSided: twoSided,
	}
	s.precompute()
	s.sampleSize = new(big.Int).Set(s.precomputed[len(s.precomputed)-1])
	if s.twoSided {
		s.sampleSize.Mul(s.sampleSize, big.NewInt(2))
	}
	return s
}

// Sample samples discrete cumulative distribution with
// precomputed values.
func (c *NormalCumulative) Sample() (*big.Int, error) {
	u, err := rand.Int(rand.Reader, c.sampleSize)
	sample := new(big.Int).Set(u)
	sign := 1

	// if we sample two sided, one bit is reserved for the sign of the output
	if c.twoSided && u.Cmp(c.precomputed[len(c.precomputed)-1]) != -1 {
		sample.Sub(sample, c.precomputed[len(c.precomputed)-1])
		sign = -1
	}
	// Find the precomputed sample
	i := sort.Search(len(c.precomputed),
		func(i int) bool { return sample.Cmp(c.precomputed[i]) != 1 })
	res := big.NewInt(int64(sign) * int64(i-1))
	return res, err
}

// precompCumu precomputes the values for sampling.
// This can be used only if sigma is not too big.
func (c *NormalCumulative) precompute() {
	cutF := new(big.Float).Mul(c.sigma, big.NewFloat(math.Sqrt(float64(c.n))))
	cut, _ := cutF.Int64()
	cut = cut + 1
	vec := make([]*big.Int, cut+1) // vec is a table of precomputed values
	vec[0] = big.NewInt(0)
	iSquare := new(big.Int)
	twoSigmaSquare := new(big.Float).Mul(c.sigma, c.sigma)
	twoSigmaSquare.Mul(twoSigmaSquare, big.NewFloat(2))
	addF := new(big.Float)
	addF.SetPrec(c.n)
	add := new(big.Int)
	for i := int64(0); i < cut; i++ {
		iSquare.SetInt64(i * i)
		// compute the value of exp(-i^2/2sigma^2) with precision n.
		// Computing the taylor polynomial with 8 * n elements suffices
		value := taylorExp(iSquare, twoSigmaSquare, 8*c.n, c.n)
		// in the case of sampling all integers, sampling 0 is counted twice
		// as positive and as negative, hence its probability must be halved
		if i == 0 && c.twoSided {
			value.Quo(value, big.NewFloat(2))
		}
		// calculate the relative probability
		addF.Mul(value, c.powNF)
		addF.Int(add)
		// save the relative probability
		vec[i+1] = new(big.Int).Add(vec[i], add)
	}
	c.precomputed = vec
}

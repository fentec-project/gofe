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
	"crypto/rand"
	"math"
	"sort"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
// This sampler is the fastest, but is limited only to cases when sigma
// is not too big, due to the sizes of the precumputed tables.
type NormalCumulative struct {
	*Normal
	preCumu []*big.Int
	twoSided bool
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalCumulative(sigma *big.Float, n int, twoSided bool) *NormalCumulative {
	s := &NormalCumulative{
		Normal:      NewNormal(sigma, n),
		preCumu:     nil,
		twoSided:    twoSided,
	}
	s.precompCumu()
	return s
}

// Sample samples discrete cumulative distribution with
// precomputed values.
//TODO: can some values be moved to constructor?
func (c *NormalCumulative) Sample() (*big.Int, error) {
	sampleSize := new(big.Int).Mul(c.preCumu[len(c.preCumu) - 1], big.NewInt(2))
	u, err := rand.Int(rand.Reader, sampleSize)
	sample := new(big.Int).Set(u)
	sign := 1

	if u.Cmp(c.preCumu[len(c.preCumu) - 1]) != -1 {
		sample.Sub(sample, c.preCumu[len(c.preCumu) - 1])
		sign = -1
	}
	// Find the precomputed sample
	i := sort.Search(len(c.preCumu), func(i int) bool {return sample.Cmp(c.preCumu[i]) != 1})
	res := big.NewInt(int64(sign) * int64(i - 1))
	return res, err
}

// precompCumu precomputes the values for sampling.
// This can be used only if sigma is not too big.
func (c *NormalCumulative) precompCumu() {
	cutF := new(big.Float).Mul(c.sigma, big.NewFloat(math.Sqrt(float64(c.n))))
	cut, _ := cutF.Int64()
	cut = cut + 1
	vec := make([]*big.Int, cut + 1) // vec is table of precomputed values
	vec[0] = big.NewInt(0)
	iSquare := new(big.Int)
	twoSigmaSquare := new(big.Float).Mul(c.sigma, c.sigma)
	twoSigmaSquare.Mul(twoSigmaSquare, big.NewFloat(2))
	addF := new(big.Float)
	addF.SetPrec(uint(c.n))
	add := new(big.Int)
	for i := int64(0); i < cut; i++ {
		iSquare.SetInt64(i * i)
		value := taylorExp(iSquare, twoSigmaSquare, 8 * c.n, c.n)
		if i == 0 && c.twoSided {
			value.Quo(value, big.NewFloat(2))
		}
		addF.Mul(value, c.powNF)
		addF.Int(add)
		vec[i + 1] = new(big.Int).Add(vec[i], add)
	}
	c.preCumu = vec
}

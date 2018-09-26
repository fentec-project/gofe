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
	"fmt"
	"math/big"
)

// NormalDouble samples random values from the
// normal (Gaussian) probability distribution, centered on 0.
// This sampler works in a way that first samples form a
// NormalCumulative with some small sigma and then using
// another sampling from uniform distribution creates a candidate
// for the output, which is accepted or rejected with certain
// probability.
type NormalDouble struct {
	*Normal
	// NormalCumulative sampler used in the first part
	samplerCumu *NormalCumulative
	// precomputed parameters used for sampling
	k      *big.Int
	twiceK *big.Int
}

// NewNormalDouble returns an instance of NormalDouble sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely samples a value.
// sigma should be a multiple of firstSigma. Increasing firstSigma a bit speeds
// up the algorithm but increases the size of the precomputed values
func NewNormalDouble(sigma *big.Float, n int, firstSigma *big.Float) *NormalDouble {
	c := NewNormalCumulative(firstSigma, n, false)
	kF := new(big.Float)
	kF.SetPrec(uint(n))
	kF.Quo(sigma, firstSigma)
	if !kF.IsInt() {
		fmt.Println("shold be an int")
	}
	k, _ := kF.Int(nil)
	twiceK := new(big.Int).Mul(k, big.NewInt(2))
	s := &NormalDouble{
		Normal:      NewNormal(sigma, n),
		samplerCumu: c,
		k:           k,
		twiceK:      twiceK,
	}
	s.preExp = s.precompExp()
	return s
}

// Sample samples according to discrete Gauss distribution using
// NormalCumulative and second sampling.
func (s *NormalDouble) Sample() (*big.Int, error) {
	// prepare values
	var sign int64
	checkValue := new(big.Int)
	uF := new(big.Float)
	uF.SetPrec(uint(s.n))
	for {
		sign = 1
		// first sample according to discrete gauss with smaller
		// sigma
		x, err := s.samplerCumu.Sample()
		if err != nil {
			return nil, err
		}
		// sample uniformly from an interval
		y, err := rand.Int(rand.Reader, s.twiceK)
		if err != nil {
			return nil, err
		}
		// use the last sampling to decide the sign of the output
		if y.Cmp(s.k) != -1 {
			sign = -1
			y.Sub(y, s.k)
		}

		// calculate the probability of the accepting the result
		checkValue.Mul(s.k, x)
		checkValue.Mul(checkValue, big.NewInt(2))
		checkValue.Add(checkValue, y)
		checkValue.Mul(checkValue, y)

		// sample if accept the output
		u, err := rand.Int(rand.Reader, s.powN)
		if err != nil {
			return nil, err
		}

		// decide if accept
		uF.SetInt(u)
		uF.Quo(uF, s.powNF)
		if s.isExpGreater(uF, checkValue) == 0 {
			// calculate the value that we accepted
			res := new(big.Int).Mul(s.k, x)
			res.Add(res, y)
			res.Mul(res, big.NewInt(sign))

			// in case the value is 0 we need to sample again to
			// decide if we accept the value, otherwise we return
			// the value
			if res.Cmp(big.NewInt(0)) == 0 {
				except, err := rand.Int(rand.Reader, big.NewInt(2))
				if err != nil {
					return nil, err
				}
				if except.Cmp(big.NewInt(0)) == 0 {

					return res, err
				}
			} else {
				return res, err
			}
		}
	}

}

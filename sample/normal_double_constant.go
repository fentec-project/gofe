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
	"math/big"
)

// NormalDouble samples random values from the
// normal (Gaussian) probability distribution, centered on 0.
// This sampler works in a way that it first samples from a
// NormalCumulative with some small sigma and then using
// another sampling from uniform distribution creates a candidate
// for the output, which is accepted or rejected with certain
// probability.
type NormalDoubleConstant struct {
	*normal
	// NormalCumulative sampler used in the first part
	samplerCDT *NormalCDT
	// precomputed parameters used for sampling
	k      *big.Int
	kSquareInv *big.Float
	twiceK *big.Int
}

// NewNormalDouble returns an instance of NormalDouble sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely samples a value.
// sigma should be a multiple of firstSigma. Increasing firstSigma a bit speeds
// up the algorithm but increases the number of precomputed values
func NewNormalDoubleConstant(k *big.Int) (*NormalDoubleConstant) {
	kSquare := new(big.Float).SetInt(k)
	kSquare.Mul(kSquare, kSquare)
	kSquareInv := new(big.Float).Quo(big.NewFloat(1), kSquare)

	twiceK := new(big.Int).Mul(k, big.NewInt(2))

	s := &NormalDoubleConstant{
		normal:      &normal{},
		samplerCDT:  NewNormalCDT(),
		k:           new(big.Int).Set(k),
		kSquareInv:  kSquareInv,
		twiceK:      twiceK,
	}

	return s
}

// Sample samples according to discrete Gauss distribution using
// NormalCumulative and second sampling.
func (s *NormalDoubleConstant) Sample() (*big.Int, error) {
	// prepare values
	var sign int64
	checkVal := new(big.Int)
	res := new(big.Int)
	uF := new(big.Float)
	uF.SetPrec(s.n)
	for {
		sign = 1
		// first sample according to discrete gauss with smaller
		// sigma
		x, err := s.samplerCDT.Sample()
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

		// partially calculate the result and the probability of accepting the result
		res.Mul(s.k, x)
		checkVal.Mul(res, big.NewInt(2))
		checkVal.Add(checkVal, y)
		checkVal.Mul(checkVal, y)
		res.Add(res, y)

		// sample from Bernoulli to decide if accept
		if Bernoulli(checkVal, s.kSquareInv) && !(res.Sign() == 0 && sign == -1) {
			// calculate the final value that we accepted
			res.Mul(res, big.NewInt(sign))

			return res, err
		}
	}

}

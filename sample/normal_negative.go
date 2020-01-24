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

	"github.com/pkg/errors"
)

// NormalNegative samples random values from the possible
// outputs of Normal (Gaussian) probability distribution centered on 0 and
// accepts or denies each sample with probability defined by the distribution
type NormalNegative struct {
	*normal
	// cut defines from which interval we sample
	cut *big.Int
	// precomputed value so we do not need to calculate it each time
	twiceCutPlusOne *big.Int
}

// NewNormalNegative returns an instance of NormalNegative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalNegative(sigma *big.Float, n uint) *NormalNegative {
	cutF := new(big.Float).Mul(sigma, big.NewFloat(math.Sqrt(float64(n))))
	cut := new(big.Int)
	cut, _ = cutF.Int(cut)
	twiceCutPlusOne := new(big.Int).Mul(cut, big.NewInt(2))
	twiceCutPlusOne = twiceCutPlusOne.Add(twiceCutPlusOne, big.NewInt(1))
	s := &NormalNegative{
		normal:          newNormal(sigma, n),
		cut:             cut,
		twiceCutPlusOne: twiceCutPlusOne,
	}
	s.preExp = s.precompExp()
	return s
}

// Sample samples a value from discrete Gaussian distribution based on
// negative (rejection) sampling.
func (c *NormalNegative) Sample() (*big.Int, error) {
	uF := new(big.Float)
	uF.SetPrec(c.n)
	nSquare := new(big.Int)

	for {
		// random sample from the interval
		n, err := rand.Int(rand.Reader, c.twiceCutPlusOne)
		if err != nil {
			return nil, errors.Wrap(err, "error while sampling")
		}
		n = n.Sub(n, c.cut)
		nSquare.Mul(n, n)

		// sample again to decide if we except the sampled value
		u, err := rand.Int(rand.Reader, c.powN)
		if err != nil {
			return nil, errors.Wrap(err, "error while sampling")
		}
		uF.SetInt(u)
		uF.Quo(uF, c.powNF)
		if !c.isExpGreater(uF, nSquare) {
			return n, nil
		}
	}
}

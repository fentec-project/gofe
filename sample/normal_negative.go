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
	"math"
	"crypto/rand"
	"github.com/pkg/errors"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
type NormalNegative struct {
	*Normal
	cut *big.Int
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalNegative(sigma *big.Float, n int) *NormalNegative {
	cutF := new(big.Float).Mul(sigma, big.NewFloat(math.Sqrt(float64(n))))
	cut := new(big.Int)
	cut, _ = cutF.Int(cut)
	s := &NormalNegative{
		Normal:      NewNormal(sigma, n),
		cut: cut,
	}
	s.preExp = s.precompExp()
	return s
}


func (c *NormalNegative) Sample() (*big.Int, error) {
	cutTimes2 := new(big.Int).Mul(c.cut, big.NewInt(2))
	cutTimes2 = cutTimes2.Add(cutTimes2, big.NewInt(1))
	uF := new(big.Float)
	uF.SetPrec(uint(c.n))
	x := new(big.Float)
	x.SetPrec(uint(c.n))
	nSquare := new(big.Int)

	// TODO maybe add an exit condition later, resulting in an error
	// to prevent infinite loop with unreasonable params
	for {
		// random sample from the interval
		n, err := rand.Int(rand.Reader, cutTimes2)
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
		if c.isExpGreater(uF, nSquare) == 0 {
			return n, nil
		}
	}
}


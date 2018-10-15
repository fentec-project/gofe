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
	"math"
	"math/big"
)

// Normal samples random values from the Normal (Gaussian)
// probability distribution, centered on 0.
type normal struct {
	// Standard deviation
	sigma *big.Float
	// Value derived form sigma used often in computations
	twoSigmaSquare *big.Float
	// Precision parameter
	n uint
	// Precomputed values of exponential function with precision n
	preExp []*big.Float
	// Precomputed values for quicker sampling
	powN  *big.Int
	powNF *big.Float
}

// NewNormal returns an instance of Normal sampler.
// It assumes mean = 0.
func newNormal(sigma *big.Float, n uint) *normal {
	powN := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(n)), nil)
	powNF := new(big.Float)
	powNF.SetPrec(n)
	powNF.SetInt(powN)
	twoSigmaSquare := new(big.Float)
	twoSigmaSquare.SetPrec(n)
	twoSigmaSquare.Mul(sigma, sigma)
	twoSigmaSquare.Mul(twoSigmaSquare, big.NewFloat(2))

	return &normal{
		sigma:          sigma,
		twoSigmaSquare: twoSigmaSquare,
		n:              n,
		preExp:         nil,
		powN:           powN,
		powNF:          powNF,
	}
}

// precompExp precomputes tje values of exp(-2^i / 2 * sigma^2) needed
// for sampling discrete Gauss distribution wit standard deviation sigma
// to arbitrary precision. This is needed since such computations present
// one of the bottlenecks of the computation. Values are precomputed in the
// interval 0 <= i < sigma^2 * sqrt(n) since for greater i the results are
// negligible.
func (c normal) precompExp() []*big.Float {
	maxFloat := new(big.Float).Mul(c.sigma, big.NewFloat(math.Sqrt(float64(c.n))))
	maxBits := maxFloat.MantExp(nil) * 2
	vec := make([]*big.Float, maxBits+1)

	x := big.NewInt(1)
	for i := 0; i < maxBits+1; i++ {
		vec[i] = taylorExp(x, c.twoSigmaSquare, 8*c.n, c.n)
		x.Mul(x, big.NewInt(2))
	}
	return vec
}

// isExpGreater outputs if y > exp(-x/(2*sigma^2)) with minimal
// calculation of exp(-x/(2*sigma^2)) based on the precomputed
// values if such values are provided. Sigma is implicit in the
// precomputed values saved in c.
func (c normal) isExpGreater(y *big.Float, x *big.Int) bool {
	// check if precomputed values are provided, if not compute
	// the exp using the taylor polynomial
	if c.preExp == nil {
		val := taylorExp(x, c.twoSigmaSquare, 8*c.n, c.n)
		if val.Cmp(y) == -1 {
			return true
		} else {
			return false
		}
	}
	// if precomputed values are not provided set up an upper and
	// lower bound for possible value of exp(-x/(2*sigma^2))
	upper := big.NewFloat(1)
	upper.SetPrec(c.n)
	lower := new(big.Float)
	lower.SetPrec(c.n)
	maxBits := x.BitLen()

	lower.Set(c.preExp[maxBits])
	lower.Quo(lower, c.preExp[0])
	if lower.Cmp(y) == 1 {
		return false
	}

	// based on bits of x and the precomputed values
	// change the upper and lower bound
	for i := 0; i < maxBits; i++ {
		bit := x.Bit(maxBits - 1 - i)
		if bit == 1 {
			upper.Mul(upper, c.preExp[maxBits-1-i])
			if y.Cmp(upper) == 1 {
				return true
			}
		} else {
			lower.Quo(lower, c.preExp[maxBits-1-i])
			if y.Cmp(lower) == -1 {
				return false
			}
		}
	}
	return false
}

// taylorExp approximates exp(-x/alpha) with taylor polynomial
// of degree k, precise at least up to 2^-n.
func taylorExp(x *big.Int, alpha *big.Float, k uint, n uint) *big.Float {
	// prepare the values for calculating the taylor polynomial of exp(x/sigma)
	res := big.NewFloat(1)
	res.SetPrec(n)

	val := new(big.Float)
	val.SetPrec(n)
	val.SetInt(x)
	val.Quo(val, alpha)

	powVal := new(big.Float)
	powVal.SetPrec(n)
	powVal.Set(val)

	factorial := new(big.Float)
	factorial.SetPrec(n)
	factorial.SetInt64(1)

	tmp := new(big.Float)
	tmp.SetPrec(n)

	// computation of the polynomial
	for i := uint(1); i <= k; i++ {
		tmp.Quo(powVal, factorial)

		res.Add(res, tmp)

		powVal.Mul(powVal, val)
		factorial.Mul(factorial, big.NewFloat(float64(i+1)))
	}
	res.Quo(big.NewFloat(1), res)

	return res
}

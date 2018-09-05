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
type Normal struct {
	// Standard deviation
	sigma *big.Float
	// Precision parameter
	n int
	// Precomputed values of exponential function with precision n
	preExp []*big.Float
	// Precomputed values for quicker sampling
	powN *big.Int
	powNF *big.Float

}

// NewNormal returns an instance of Normal sampler.
// It assumes mean = 0.
func NewNormal(sigma *big.Float, n int) *Normal {
	powN := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(n)), nil)
	powNF := new(big.Float)
	powNF.SetPrec(uint(n))
	powNF.SetInt(powN)
	s := &Normal{
		sigma:    sigma,
		n:        n,
		preExp:   nil,
		powN:     powN,
		powNF:    powNF,
	}
	return s
}



// an approximation of a exp(-x/alpha) with taylor
// polynomial of degree k, precise at least up to 2^{-n}
func taylorExp(x *big.Int, alpha *big.Float, k int, n int) *big.Float {
	// prepare the values for calculating the taylor polynomial of exp(x/sigma)
	res := big.NewFloat(1)
	res.SetPrec(uint(n))

	value := new(big.Float)
	value.SetPrec(uint(n))
	value.SetInt(x)
	value.Quo(value, alpha)

	powerValue := new(big.Float)
	powerValue.SetPrec(uint(n))
	powerValue.Set(value)

	factorial := new(big.Float)
	factorial.SetPrec(uint(n))
	factorial.SetInt64(1)

	tmp := new(big.Float)
	tmp.SetPrec(uint(n))

	// computation of the polynomial
	for i := 1; i <= k; i++ {
		tmp.Quo(powerValue, factorial)

		res.Add(res, tmp)

		powerValue.Mul(powerValue, value)
		factorial.Mul(factorial, big.NewFloat(float64(i + 1)))
	}
	res.Quo(big.NewFloat(1), res)

	return res
}

// Precomputation of values of exp(-i / 2 * sigma^2) needed
// for sampling discrete Gauss distribution wit standard deviation sigma
// to arbitrary precision. This is needed since such computations present
// one of the bottlenecks of the computation. Values are precomputed up to
// i < sigma^2 * sqrt(n) since for greater i the results are negligible.
func (c Normal) precompExp() []*big.Float {
	maxFloat := new(big.Float).Mul(c.sigma, big.NewFloat(math.Sqrt(float64(c.n))))
	maxBits := maxFloat.MantExp(nil) * 2
	vec := make([]*big.Float, maxBits + 1)

	twoSigmaSquare := new(big.Float)
	twoSigmaSquare.SetPrec(uint(c.n))
	twoSigmaSquare.Mul(c.sigma, c.sigma)
	twoSigmaSquare.Mul(twoSigmaSquare, big.NewFloat(2))

	x := big.NewInt(1)
	for i := 0; i < maxBits + 1; i++ {
		vec[i] = taylorExp(x, twoSigmaSquare, 8 * c.n, c.n)
		x.Mul(x, big.NewInt(2))
	}
	return vec
}


// Function decides if y > exp(-x/(2*sigma^2)) with minimal calculation of
// exp(-x/(2*sigma^2)) based on the precomputed values.
// Sigma is implicit in the precomputed values saved in c.
func (c Normal) isExpGreater(y *big.Float, x *big.Int) int {
	// set up an upper and lower bound for possible value of
	// exp(-x/(2*sigma^2))
	upper := big.NewFloat(1)
	upper.SetPrec(uint(c.n))
	lower := new(big.Float)
	lower.SetPrec(uint(c.n))
	maxBits := x.BitLen()

	lower.Set(c.preExp[maxBits])
	lower.Quo(lower, c.preExp[0])
	if lower.Cmp(y) == 1 {
		return 0
	}

	// based on bits of x and the precomputed values
	// change the upper and lower bound
	for i := 0; i < maxBits; i++ {
		bit := x.Bit(maxBits - 1 - i)
		if bit == 1 {
			upper.Mul(upper, c.preExp[maxBits - 1 - i])
			if y.Cmp(upper) == 1 {
				return 1
			}
		} else {
			lower.Quo(lower, c.preExp[maxBits - 1 - i])
			if y.Cmp(lower) == -1 {
				return 0
			}
		}
	}
	return 0
}

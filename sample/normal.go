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
	"encoding/binary"
	"math"
	"math/big"
)

// Normal samples random values from the Normal (Gaussian)
// probability distribution, centered on 0.
type normal struct {
	// Standard deviation
	sigma *big.Float
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

	return &normal{
		sigma:  sigma,
		n:      n,
		preExp: nil,
		powN:   powN,
		powNF:  powNF,
	}
}

// expCoef are coefficients of a polynomial approximating an exponential
// function.
var expCoef = []float64{1.43291003789439094275872613876154915146798884961754e-7,
	1.2303944375555413249736938854916878938183799618855e-6,
	1.5359914219462011698283041005730353845137869939208e-5,
	1.5396043210538638053991311593904356413986533880234e-4,
	1.3333877552501097445841748978523355617653578519821e-3,
	9.6181209331756452318717975913386908359825611114502e-3,
	5.5504109841318247098307381293125217780470848083496e-2,
	0.24022650687652774559310842050763312727212905883789,
	0.69314718056193380668617010087473317980766296386719,
	1}

var mantissaPrecision = uint64(52)
var mantissaMask = (uint64(1) << mantissaPrecision) - 1
var bitLenForSample = uint64(19)
var maxExp = uint64(1023)
var cmpMask = uint64(1) << 61

// Bernoulli returns true with probability proportional to
// 2^{-t/l^2}. A polynomial approximation is used to evaluate
// the exponential function. The implementation is based on paper:
// "FACCT: FAst, Compact, and Constant-Time Discrete Gaussian
// Sampler over Integers" by R. K. Zhao, R. Steinfeld, and A. Sakzad
// (https://eprint.iacr.org/2018/1234.pdf). See the above paper where
// it is argued that such a sampling achieves a relative error at most
// 2^{-45} with the chosen parameters.
func Bernoulli(t *big.Int, lSquareInv *big.Float) (bool, error) {
	aBig := new(big.Float).SetInt(t)
	aBig.Mul(aBig, lSquareInv)
	a, _ := aBig.Float64()
	a = -a

	negFloorA := -math.Floor(a)
	z := a + negFloorA

	powOfZ := expCoef[0]
	for i := 1; i < 10; i++ {
		powOfZ = powOfZ*z + expCoef[i]
	}

	powOfAMantissa := math.Float64bits(powOfZ) & mantissaMask
	powOfAExponent := (math.Float64bits(powOfZ) >> mantissaPrecision) - uint64(negFloorA)

	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		return false, err
	}

	r1 := binary.LittleEndian.Uint64(randBytes[0:8])
	r1 = r1 >> (64 - (mantissaPrecision + 1))
	r2 := binary.LittleEndian.Uint64(randBytes[8:16])
	r2 = r2 >> (64 - bitLenForSample)

	check1 := powOfAMantissa | (uint64(1) << mantissaPrecision)
	check2 := uint64(1) << (bitLenForSample + powOfAExponent + 1 - maxExp)

	// constant time check if r1 < check1 && r2 < check2
	return (cmpMask & (r1 - check1) & (r2 - check2)) > 0 || powOfZ == 1, nil
}

// precompExp precomputes the values of exp(-2^i / 2 * sigma^2) needed
// for sampling discrete Gauss distribution wit standard deviation sigma
// to arbitrary precision. This is needed since such computations present
// one of the bottlenecks of the computation. Values are precomputed in the
// interval 0 <= i < sigma^2 * sqrt(n) since for greater i the results are
// negligible.
func (c normal) precompExp() []*big.Float {
	maxFloat := new(big.Float).Mul(c.sigma, big.NewFloat(math.Sqrt(float64(c.n))))
	maxBits := maxFloat.MantExp(nil) * 2
	vec := make([]*big.Float, maxBits+1)

	twoSigmaSquare := new(big.Float)
	twoSigmaSquare.SetPrec(c.n)
	twoSigmaSquare.Mul(c.sigma, c.sigma)
	twoSigmaSquare.Mul(twoSigmaSquare, big.NewFloat(2))

	x := big.NewInt(1)
	for i := 0; i < maxBits+1; i++ {
		vec[i] = taylorExp(x, twoSigmaSquare, 8*c.n, c.n)
		x.Mul(x, big.NewInt(2))
	}
	return vec
}

// isExpGreater outputs if y > exp(-x/(2*sigma^2)) with minimal
// calculation of exp(-x/(2*sigma^2)) based on the precomputed
// values. Sigma is implicit in the precomputed values saved in c.
func (c normal) isExpGreater(y *big.Float, x *big.Int) bool {
	// set up an upper and lower bound for possible value of
	// exp(-x/(2*sigma^2))
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

	// set up a minimal value up to which it calculates the precision
	oneOverEps := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(n)), nil)
	eps := new(big.Float)
	eps.SetPrec(n)
	eps.SetInt(oneOverEps)
	eps.Quo(big.NewFloat(1), eps)

	// computation of the polynomial
	for i := uint(1); i <= k; i++ {
		tmp.Quo(powVal, factorial)

		res.Add(res, tmp)

		powVal.Mul(powVal, val)
		factorial.Mul(factorial, big.NewFloat(float64(i+1)))
		if tmp.Cmp(eps) == -1 {
			break
		}
	}
	res.Quo(big.NewFloat(1), res)

	return res
}

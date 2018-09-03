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
	"fmt"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
// This sampler is the fastest, but is limited only to cases when sigma
// is not too big, due to the sizes of the precumputed tables.
type NormalDouble struct {
	*Normal
	samplerCumu *NormalCumulative
	k *big.Int
	twiceK *big.Int
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
// sigma should be a multiple of firstSigma
func NewNormalDouble(sigma *big.Float, n int, firstSigma *big.Float) *NormalDouble {
	c := NewNormalCumulative(firstSigma, n, false)
	kF := new(big.Float).Quo(sigma, firstSigma)
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

// Sample samples discrete cumulative distribution with
// precomputed values.
//TODO: can some values be moved to constructor?
func (s *NormalDouble) Sample() (*big.Int, error) {
	sign := 1
	checkValue := new(big.Int)
	uF := new(big.Float)
	uF.SetPrec(uint(s.n))
	for {
		sign = 1
		x, err := s.samplerCumu.Sample()
		if err != nil {
			return nil, err
		}
		y, err := rand.Int(rand.Reader, s.twiceK)
		if err != nil {
			return nil, err
		}

		//fmt.Println(y, s.k, y.Cmp(s.k))
		if y.Cmp(s.k) != -1{
			sign = -1
			y.Sub(y, s.k)
		}
		//fmt.Println(y, s.k, sign)
		checkValue.Mul(s.k, x)
		checkValue.Mul(checkValue, big.NewInt(2))
		checkValue.Add(checkValue, y)
		checkValue.Mul(checkValue, y)

		u, err := rand.Int(rand.Reader, s.powN)
		if err != nil {
			return nil, err
		}
		uF.SetInt(u)
		uF.Quo(uF, s.powNF)
		if s.isExpGreater(uF, checkValue) == 0 {
			res := new(big.Int).Mul(s.k, x)
			res.Add(res, y)
			res.Mul(res, big.NewInt(int64(sign)))
			if res.Cmp(big.NewInt(0)) == 0 {
				//fmt.Println("zero")
				except, err := rand.Int(rand.Reader, big.NewInt(2))
				if err != nil {
					return nil, err
				}
				if except.Cmp(big.NewInt(0)) == 0 {
					//fmt.Println("except")

					return res, err
				}
			} else {
				return res, err
			}
		}
	}

}


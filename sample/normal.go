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
	"math/rand"
)

// Normal samples random values from the Normal (Gaussian)
// probability distribution, centered on 0.
type Normal struct {
	// Mean
	// mu float64 // TODO Add if necessary. Currently mu = 0 is assumed
	// Standard deviation
	sigma float64
	// Variance
	variance float64
	// Sampling precision.
	// This parameter tells us how close we are to uniformly
	// sampling from the interval [0,1]
	eps float64
	// Limit for the sampling interval.
	// Events outside this interval are highly unlikely.
	k float64

	// The interval for sampling
	cut int
}

// NewNormal returns an instance of Normal sampler.
// It assumes mean = 0.
func NewNormal(sigma, eps, k float64) *Normal {
	return &Normal{
		sigma:    sigma,
		variance: sigma * sigma,
		eps:      eps,
		k:        k,
		cut:      int(sigma * math.Sqrt(k)),
	}
}

func (g *Normal) density(x float64) float64 {
	return math.Exp(-x * x / g.variance)
}

func (g *Normal) Sample() (*big.Int, error) {
	cutTimes2 := 2*g.cut + 1 // TODO check consistency - do we need + 1?

	var x, u float64

	// TODO maybe add an exit condition later, resulting in an error
	// to prevent infinite loop with unreasonable params
	for {
		// random sample from the interval
		x = float64(rand.Intn(cutTimes2) - g.cut)
		u = float64(rand.Intn(int(g.eps)))

		if u < g.density(x)*g.eps {
			return new(big.Int).SetInt64(int64(x)), nil
		}
	}
}

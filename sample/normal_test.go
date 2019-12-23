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

package sample_test

import (
	"testing"

	"math/big"

	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func mean(vec []*big.Int) *big.Float {
	meanI := big.NewInt(0)
	for i := 0; i < len(vec); i++ {
		meanI.Add(meanI, vec[i])
	}
	ret := new(big.Float).SetInt(meanI)
	ret.Quo(ret, big.NewFloat(float64(len(vec))))
	return ret
}

func variance(vec []*big.Int) *big.Float {
	meanI := big.NewInt(0)
	square := new(big.Int)
	for i := 0; i < len(vec); i++ {
		square.Mul(vec[i], vec[i])
		meanI.Add(meanI, square)
	}
	ret := new(big.Float).SetInt(meanI)
	ret.Quo(ret, big.NewFloat(float64(len(vec))))
	return ret
}

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type paramBounds struct {
	meanLow, meanHigh, varLow, varHigh float64
}

// testNormalSampler takes a normal sampler and checks whether
// it is producing expected results - such that mean and variance
// of a series of samples are within acceptable bounds.
func testNormalSampler(t *testing.T, s sample.Sampler, bounds paramBounds) {
	vec := make([]*big.Int, 100000)
	for i := 0; i < len(vec); i++ {
		vec[i], _ = s.Sample()
	}

	me, _ := mean(vec).Float64()
	v, _ := variance(vec).Float64()

	// me should be around 0 and v should be around 100
	assert.True(t, me > bounds.meanLow, "mean value of the normal distribution is too small")
	assert.True(t, me < bounds.meanHigh, "mean value of the normal distribution is too big")
	assert.True(t, v > bounds.varLow, "variance of the normal distribution is too small")
	assert.True(t, v < bounds.varHigh, "variance of the normal distribution is too big")
}

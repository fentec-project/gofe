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

// UniformRange samples random values from the interval [min, max).
type UniformRange struct {
	min *big.Int
	max *big.Int
}

// NewUniformRange returns an instance of the UniformRange sampler.
// It accepts lower and upper bounds on the sampled values.
func NewUniformRange(min, max *big.Int) *UniformRange {
	return &UniformRange{
		min: min,
		max: max,
	}
}

// Sample samples random values from the interval [min, max).
func (u *UniformRange) Sample() (*big.Int, error) {
	maxMinusMin := new(big.Int).Sub(u.max, u.min)
	res, err := rand.Int(rand.Reader, maxMinusMin)
	if err != nil {
		return nil, err
	}

	res.Add(res, u.min)

	return res, err
}

// Uniform samples random values from the interval [0, max).
type Uniform struct {
	UniformRange
}

// NewUniform returns an instance of the Uniform sampler.
// It accepts an upper bound on the sampled values.
func NewUniform(max *big.Int) *UniformRange {
	return NewUniformRange(big.NewInt(0), max)
}

// Sample samples random values from the interval [0, max).
func (u *Uniform) Sample() (*big.Int, error) {
	return rand.Int(rand.Reader, u.max)
}

// Bit samples a single random bit (value 0 or 1).
type Bit struct {
	Uniform
}

// NewBit returns an instance of Bit sampler.
func NewBit() *UniformRange {
	return NewUniform(big.NewInt(2))
}

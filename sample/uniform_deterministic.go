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

	"golang.org/x/crypto/salsa20"
)

// UniformRange samples random values from the interval [0, max).
type UniformDet struct {
	key *[32]byte
	max *big.Int
	maxBits int
}

// NewUniformRange returns an instance of the UniformRange sampler.
// It accepts lower and upper bounds on the sampled values.
func NewUniformDet(max *big.Int, key *[32]byte) *UniformDet {
	maxBits := new(big.Int).Sub(max, big.NewInt(1)).BitLen()
	return &UniformDet{
		key:      key,
		max:      max,
		maxBits: maxBits,
	}
}

// UniformRange samples random values from the interval [min, max).
func (u *UniformDet) Sample() (*big.Int) {
	maxBytes := (u.maxBits / 8) + 1
	over := uint(8 - (u.maxBits % 8))
	if over == 8 {
		maxBytes -= 1
		over = 0
	}
	var ret *big.Int
	for {
		in := make([]byte, maxBytes)
		out := make([]byte, maxBytes)
		for i := range in { in[i] = 0 }
		nounce := make([]byte, 8)
		for i := range nounce { nounce[i] = 0 }

		salsa20.XORKeyStream(out, in, nounce, u.key)

		out[0] = out[0] >> over
		ret = new(big.Int).SetBytes(out)
		break
	}
	return ret
}

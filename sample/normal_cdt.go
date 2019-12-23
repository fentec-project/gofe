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
	"math/big"
)

// cdtTable consists of a precomputed table of values
// using which one can create a constant time half-Gaussian
// sampler with sigma = sqrt(1/2ln(2))
var cdtTable = [][2]uint64{{2200310400551559144, 3327841033070651387},
	{7912151619254726620, 380075531178589176},
	{5167367257772081627, 11604843442081400},
	{5081592746475748971, 90134450315532},
	{6522074513864805092, 175786317361},
	{2579734681240182346, 85801740},
	{8175784047440310133, 10472},
	{2947787991558061753, 0},
	{22489665999543, 0}}

var cdtLen = 9 // upper bound on sample values

var cdtLowMask uint64 = 0x7fffffffffffffff

// SigmaCDT is a constant sqrt(1/(2ln(2)))
var SigmaCDT, _ = new(big.Float).SetString("0.84932180028801904272150283410")

// NormalCDT samples random values from the discrete Normal (Gaussian)
// probability distribution, limited to non-negative values (half-Gaussian).
// In particular each value x from Z^+ is sampled with probability proportional to
// exp(-x^2/sigma^2) where sigma = sqrt(1/2ln(2)).
// The implementation is based on paper:
// "FACCT: FAst, Compact, and Constant-Time Discrete Gaussian
// Sampler over Integers" by R. K. Zhao, R. Steinfeld, and A. Sakzad
// (https://eprint.iacr.org/2018/1234.pdf). See the above paper where
// it is argued that such a sampling achieves a relative error at most
// 2^{-46} with the chosen parameters.
type NormalCDT struct {
	*normal
}

// NewNormalCDT returns an instance of NormalCDT sampler.
func NewNormalCDT() *NormalCDT {
	s := &NormalCDT{}
	return s
}

// Sample samples discrete non-negative values with Gaussian
// distribution.
func (c *NormalCDT) Sample() (*big.Int, error) {
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	r1 := binary.LittleEndian.Uint64(randBytes[0:8])
	r1 = r1 & cdtLowMask
	r2 := binary.LittleEndian.Uint64(randBytes[8:16])
	r2 = r2 & cdtLowMask

	x := uint64(0)
	for i := 0; i < cdtLen; i++ {
		x += (((r1 - cdtTable[i][0]) & ((uint64(1) << 63) ^ ((r2 - cdtTable[i][1]) | (cdtTable[i][1] - r2)))) | (r2 - cdtTable[i][1])) >> 63
	}

	return big.NewInt(int64(x)), nil
}

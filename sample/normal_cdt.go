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
	"encoding/binary"
	"fmt"
)

/* CDT table */
var cdtTable = [][2]uint64{{2200310400551559144, 3327841033070651387},
	{7912151619254726620, 380075531178589176},
	{5167367257772081627, 11604843442081400},
	{5081592746475748971, 90134450315532},
	{6522074513864805092, 175786317361},
	{2579734681240182346, 85801740},
	{8175784047440310133, 10472},
	{2947787991558061753, 0},
	{22489665999543, 0}}

var cdtLen = 9 /* [0..tau*sigma]=[0..9] */

var cdtLowMask uint64 = 0x7fffffffffffffff


// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
// This sampler is the fastest, but is limited only to cases when sigma
// is not too big, due to the sizes of the precomputed tables.
type NormalCDT struct {
	*normal
}

// NewNormalCumulative returns an instance of NormalCumulative sampler.
// It assumes mean = 0. Values are precomputed when this function is
// called, so that Sample merely returns a precomputed value.
func NewNormalCDT() *NormalCDT {
	s := &NormalCDT{}
	return s
}

// Sample samples discrete cumulative distribution with
// precomputed values.
func (c *NormalCDT) Sample() (*big.Int, error) {
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err!=nil {
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

	fmt.Println(x)
	return big.NewInt(int64(x)), nil
}



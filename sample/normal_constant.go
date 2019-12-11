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
	"math/rand"
	"time"
	"math"
	"math/big"
	cran "crypto/rand"
	"encoding/binary"
)

// NormalCumulative samples random values from the
// cumulative Normal (Gaussian) probability distribution, centered on 0.
// This sampler is the fastest, but is limited only to cases when sigma
// is not too big, due to the sizes of the precomputed tables.
type NormalCDT2 struct {
	*normal
}


/* CDT table */
var CDT = [][2]uint64{{2200310400551559144, 3327841033070651387},
					  {7912151619254726620, 380075531178589176},
					  {5167367257772081627, 11604843442081400},
					  {5081592746475748971, 90134450315532},
					  {6522074513864805092, 175786317361},
					  {2579734681240182346, 85801740},
					  {8175784047440310133, 10472},
					  {2947787991558061753, 0},
					  {22489665999543, 0}}

var CDT_LENGTH = 9 /* [0..tau*sigma]=[0..9] */

var CDT_LOW_MASK uint64 = 0x7fffffffffffffff



// Sample samples discrete cumulative distribution with
// precomputed values.
func (c *NormalCDT2) Sample2() (uint64) {
	//uint64_t x = 0;
	//uint64_t r1, r2;
	//uint32_t i;
	//
	//r1 = (*((uint64_t *)r)) & CDT_LOW_MASK;
	//r2 = (*((uint64_t *)(r + 8))) & CDT_LOW_MASK;
	//
	//for (i = 0; i < CDT_LENGTH; i++)
	//{
	//x += (((r1 - CDT[i][0]) & ((1LL << 63) ^ ((r2 - CDT[i][1]) | (CDT[i][1] - r2)))) | (r2 - CDT[i][1])) >> 63;
	//}
	//

	var x, r1, r2, one uint64

	one = 1
	x = 0
	rand.Seed(time.Now().UnixNano())
	r1 = rand.Uint64()
	r1 = r1 & CDT_LOW_MASK
	r2  = rand.Uint64()
	r2 = r2 & CDT_LOW_MASK
	//fmt.Println(r1, r2)

	for i := 0; i < CDT_LENGTH; i++ {
		x += (((r1 - CDT[i][0]) & ((one << 63) ^ ((r2 - CDT[i][1]) | (CDT[i][1] - r2)))) | (r2 - CDT[i][1])) >> 63
	}

	//fmt.Println(x)

	return x;
}

/* coefficients of the exp evaluation polynomial */
var exp_coef = []uint64{0x3e833b70ffa2c5d4,
0x3eb4a480fda7e6e1,
0x3ef01b254493363f,
0x3f242e0e0aa273cc,
0x3f55d8a2334ed31b,
0x3f83b2aa56db0f1a,
0x3fac6b08e11fc57e,
0x3fcebfbdff556072,
0x3fe62e42fefa7fe6,
0x3ff0000000000000}

var expCoef  = []float64{1.43291003789439094275872613876154915146798884961754e-7,
						 1.2303944375555413249736938854916878938183799618855e-6,
						 1.5359914219462011698283041005730353845137869939208e-5,
						 1.5396043210538638053991311593904356413986533880234e-4,
						 1.3333877552501097445841748978523355617653578519821e-3,
						 9.6181209331756452318717975913386908359825611114502e-3,
						 5.5504109841318247098307381293125217780470848083496e-2,
						 0.24022650687652774559310842050763312727212905883789,
						 0.69314718056193380668617010087473317980766296386719,
						 1}

var BERNOULLI_ENTRY_SIZE = uint64(9)
var EXP_MANTISSA_PRECISION = uint64(52)
var R_MANTISSA_PRECISION = (EXP_MANTISSA_PRECISION + 1)
var EXP_MANTISSA_MASK = (uint64(1) << EXP_MANTISSA_PRECISION) - 1
var bitLenForSample = uint64(19)
var maxExp = uint64(1023)

func (c *NormalCDT2) Bernoulli2(t uint64, k uint64) (uint64) {
	//randBytes := make([]byte, 1)
	//cran.Read(randBytes)

	//cc := binary.LittleEndian.Uint64(randBytes)
	//fmt.Println(cc)



	a := -float64(t)/float64(k * k)

	negfloorA := -math.Floor(a)
	z := a + negfloorA

	zSum := z * expCoef[0] + expCoef[1]
	for i:=2; i < 10; i++ {
		//fmt.Println("exp ceof", expCoef[i])
		zSum = zSum * z + expCoef[i]
	}

	//zSum = zSum * math.Pow(2, floorA)

	//fmt.Println(z, zSum, math.Pow(2, z), uint64(zSum))

	//fmt.Println("zsum", zSum)
	//fmt.Println("floora", floorA)

	//res_mantissa := (math.Float64bits(zSum) & EXP_MANTISSA_MASK) | (uint64(1) << EXP_MANTISSA_PRECISION);
	res_mantissa := (math.Float64bits(zSum) & EXP_MANTISSA_MASK)
	res_exponent :=  (math.Float64bits(zSum) >> EXP_MANTISSA_PRECISION) - uint64(negfloorA);

	//fmt.Println("mantissa, exp, mant*2^mindel", res_mantissa, res_exponent, float64(res_mantissa) / math.Pow(float64(2), float64(53)))

	//fmt.Println("res", (1 +(float64(res_mantissa) / math.Pow(float64(2), float64(52)))) * math.Pow(float64(2), float64(res_exponent) - 1023))

	rand.Seed(time.Now().UnixNano())


	r1 := rand.Uint64()
	r1 = r1 >> (64 - (EXP_MANTISSA_PRECISION +1))
	r2 := rand.Uint64()
	r2 = r2 >> (64 - (bitLenForSample))

	//fmt.Println(r1, r2)

	//fmt.Println("exp", res_exponent)

	check1 := res_mantissa | (uint64(1) << EXP_MANTISSA_PRECISION);
	check2 := uint64(1) << (19 + res_exponent + 1 -1023)
	//fmt.Println(r1, check1, r2, check2)

	if r1 < check1 && r2 < check2 {
		return 1
	}

	return 0
	//fmt.Println(uint64(10) - uint64(11))

	//
	//
	//mant := big.NewFloat(0)
	//x := big.NewFloat(zSum)
	//exp := x.MantExp(mant)
	//e2 := math.Pow(2, float64(-53 + exp))
	//e1 := math.Pow(2, float64(exp))
	//
	////mant_f, _ := mant.Float64()
	//
	//test := e1 + e2* float64(res_mantissa)
	//
	//
	//
	////res_exponent = R_EXPONENT_L - 1023 + 1 + (res >> EXP_MANTISSA_PRECISION);
	//
	//fmt.Println(exp, mant, math.Float64bits(zSum), res_mantissa, test)
	//
	//
	//te := float64(1)
	////te := float64(1)
	//fmt.Println(math.Float64bits(te), math.Float64bits(te + 1))
	//
	//fmt.Println(math.Float64frombits(0x3e833b70ffa2c5d4), EXP_MANTISSA_MASK, uint64(1) << 2)
}



func (c *NormalCDT) Bernoulli(t *big.Int, kSquareInv *big.Float) (bool) {
	aBig := new(big.Float).SetInt(t)
	aBig.Mul(aBig, kSquareInv)
	a, _ := aBig.Float64()
	a = -a

	negFloorA := -math.Floor(a)
	z := a + negFloorA

	powOfZ := expCoef[0]
	for i := 1; i < 10; i++ {
		powOfZ = powOfZ*z + expCoef[i]
	}

	powOfAMantissa := math.Float64bits(powOfZ) & EXP_MANTISSA_MASK
	powOfAExponent := (math.Float64bits(powOfZ) >> EXP_MANTISSA_PRECISION) - uint64(negFloorA)

	randBytes := make([]byte, 16)
	cran.Read(randBytes)

	r1 := binary.LittleEndian.Uint64(randBytes[0:8])
	r1 = r1 >> (64 - (EXP_MANTISSA_PRECISION + 1))
	r2 := binary.LittleEndian.Uint64(randBytes[8:16])
	r2 = r2 >> (64 - bitLenForSample)

	check1 := powOfAMantissa | (uint64(1) << EXP_MANTISSA_PRECISION)
	check2 := uint64(1) << (bitLenForSample + powOfAExponent + 1 - maxExp)
	if r1 < check1 && r2 < check2 {
		return true
	}

	return false
}































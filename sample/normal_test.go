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
	"testing"

	"github.com/stretchr/testify/assert"
	"math/big"
	"fmt"
)


//double variance(vector *vec) {
//double x = 0;
//mpz_t value;
//mpz_init(value);
//for (int i = 0; i < vec->size; i++) {
//vector_get(value, vec, i);
//x = x + mpz_get_d(value) * mpz_get_d(value);
//}
//x = x / (double)vec->size;
//return x;
//}

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


func TestSimple_Normal(t *testing.T) {

	//res := taylorExp(big.NewInt(1), big.NewFloat(1), 1000, 512)
	//fmt.Println(res)
	c := NewNormalNegative(big.NewFloat(10), 256)
	vec := make([]*big.Int, 10000)
	for i := 0; i < len(vec); i++ {
		vec[i], _ = c.Sample()
	}
	me := mean(vec)
	v := variance(vec)
	fmt.Println(me, v)



	c2 := NewNormalCumulative(big.NewFloat(10), 256, true)
	for i := 0; i < len(vec); i++ {
		vec[i], _ = c2.Sample()
	}
	me = mean(vec)
	v = variance(vec)
	fmt.Println(me, v)

	c3 := NewNormalDouble(big.NewFloat(10), 256, big.NewFloat(1))
	for i := 0; i < len(vec); i++ {
		vec[i], _ = c3.Sample()
	}
	me = mean(vec)
	v = variance(vec)
	fmt.Println(me, v)

	assert.Equal(t, 1, 1, "Original and decrypted values should match")
}

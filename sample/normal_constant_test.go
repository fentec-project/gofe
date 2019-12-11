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

	"github.com/fentec-project/gofe/sample"
	"fmt"
)

func variance2(vec []uint64) (float64, float64) {
	varian := uint64(0)
	me := uint64(0)
	for i := 0; i < len(vec); i++ {
		square := vec[i] * vec[i]
		varian += square
		me += vec[i]
	}

	return float64(varian) / float64(len(vec)), float64(me) / float64(len(vec))
}

func TestNormalConstant(t *testing.T) {
	r := sample.NormalCDT2{}

	vec := make([]uint64, 100000)
	for i := 0; i < len(vec); i++ {
		vec[i] = r.Sample2()
	}

	ve, me := variance2(vec)

	fmt.Println(ve, me)

	count := float64(0)
	//u := big.NewInt(10)
	//kInv := big.NewFloat(float64(1) / 16)
	for i := 0; i < 100000000; i++ {
		//if r.Bernoulli2(u, kInv) {
		//	count++
		//}
		count += float64(r.Bernoulli2(10, 4))
	}

	fmt.Println("ber", count/100000000)
}

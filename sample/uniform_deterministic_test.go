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
	"math/big"
	"fmt"
)

func TestUniformDet(t *testing.T) {
	samper := sample.NewUniform(big.NewInt(256))
	var key [32]byte
	for i := range key {
		r, _ := samper.Sample()
		key[i] = byte(r.Int64())
	}
	sampler := sample.NewUniformDet(big.NewInt(4), &key)
	val := sampler.Sample()
	fmt.Println(val)
}

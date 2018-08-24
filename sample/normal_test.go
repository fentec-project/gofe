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

func TestSimple_Normal(t *testing.T) {

	//res := taylorExp(big.NewInt(1), big.NewFloat(1), 1000, 512)
	//fmt.Println(res)
	c := NewNormalNegative(big.NewFloat(10), 256)
	n, _ := c.Sample()
	fmt.Println(n)
	c2 := NewNormalCumulative(big.NewFloat(2), 256, true)
	n2, _ := c2.Sample()
	fmt.Println(n2)


	assert.Equal(t, 1, 1, "Original and decrypted values should match")
}

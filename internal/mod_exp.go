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

package internal

import "math/big"

// ModExp calculates g^x in Z_m*, even if x < 0.
func ModExp(g, x, m *big.Int) *big.Int {
	ret := new(big.Int)
	if x.Sign() == -1 {
		xNeg := new(big.Int).Neg(x)
		ret.Exp(g, xNeg, m)
		ret.ModInverse(ret, m)
	} else {
		ret.Exp(g, x, m)
	}

	return ret
}

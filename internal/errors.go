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

import (
	"fmt"
)

var malformedStr = "is not of the proper form"

var MalformedPubKey = fmt.Errorf("public key %s", malformedStr)
var MalformedSecKey = fmt.Errorf("secret key %s", malformedStr)
var MalformedDecKey = fmt.Errorf("decryption key %s", malformedStr)
var MalformedCipher = fmt.Errorf("ciphertext %s", malformedStr)
var MalformedInput = fmt.Errorf("input data %s", malformedStr)

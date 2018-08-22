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
	"errors"
	"fmt"
)

var malformedStr = "is not of the proper form"

var MalformedPubKey = errors.New(fmt.Sprintf("public key %s", malformedStr))
var MalformedSecKey = errors.New(fmt.Sprintf("secret key %s", malformedStr))
var MalformedDecKey = errors.New(fmt.Sprintf("decryption key %s", malformedStr))
var MalformedCipher = errors.New(fmt.Sprintf("ciphertext %s", malformedStr))
var MalformedInput = errors.New(fmt.Sprintf("input data %s", malformedStr))

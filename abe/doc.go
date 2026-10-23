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

// Package abe includes schemes allowing attribute based encryption.
//
// Note that the schemes in this library are IND-CPA secure; i.e. they are
// designed to be secure against arbitrary plaintexts.
//
// They are not, however, designed to withstand arbitrary supplied ciphertexts
// at decryption. Because ABE must check satisfaction before decryption,
// policies must be fully processed, which takes time. Further, policies are
// presumed to be the same as at encryption.
//
// Users should, therefore, authenticate the ciphertext such that it is obvious
// when a policy is not the same, prior to attempting to decrypt using this
// library.
package abe

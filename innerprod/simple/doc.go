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

// Package simple includes simple schemes for functional encryption of
// inner products.
//
// All implementations in this package are based on the reference
// paper by  Abdalla et. al (see https://eprint.iacr.org/2015/017.pdf).
// The reference scheme offers selective security under chosen-plaintext
// attacks (s-IND-CPA security).
//
// The reference scheme is public key, which means that no master secret
// key is required for the encryption.
//
// For instantiation from the decisional Diffie-Hellman assumption
// (DDH), see struct DDH (and its multi-input variant DDHMulti, which
// is a secret key scheme, because a part of the secret key is required
// for the encryption).
//
// For instantiation from learning with errors (LWE), see
// structs LWE and RingLWE.
package simple

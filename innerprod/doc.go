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

// Package innerprod includes functional encryption schemes for inner
// products.
//
// Based on security assumptions, the schemes are organized into
// subpackages simple (s-IND-CPA security), and fullysec
// (e.g. "fully secure", offering adaptive IND-CPA security).
//
// Note that in both packages you will find single input as
// well as multi input schemes. Construction of all multi input
// schemes is based on the work of Abdalla et. al (see paper:
// https://eprint.iacr.org/2017/972.pdf)
package innerprod

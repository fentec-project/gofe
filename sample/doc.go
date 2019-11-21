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

// Package sample includes samplers for sampling random values
// from different probability distributions.
//
// Package sample provides the Sampler interface
// along with different implementations of this interface.
// Its primary purpose is support choosing random *big.Int values
// from selected probability distributions.
//
// Implementations of the Sampler interface can be used,
// for instance, to fill vector or matrix structures with
// the desired random data.
package sample

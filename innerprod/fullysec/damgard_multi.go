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

package fullysec

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// DamgardMulti represents a multi input variant of the
// underlying Damgard scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
type DamgardMulti struct {
	// number of encryptors
	Slots int
	*Damgard
}

// NewDamgardMulti configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors l, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded.
//
// It returns an error in case the underlying Damgard scheme
// instances could not be properly instantiated.
func NewDamgardMulti(slots, l, modulusLength int, bound *big.Int) (*DamgardMulti, error) {
	damgard, err := NewDamgard(l, modulusLength, bound)
	if err != nil {
		return nil, err
	}

	return &DamgardMulti{
		Slots:   slots,
		Damgard: damgard,
	}, nil
}

// NewDamgardMultiFromParams takes the number of slots and configuration
// parameters of an existing Damgard scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new DamgardMulti instance.
func NewDamgardMultiFromParams(slots int, params *DamgardParams) *DamgardMulti {
	return &DamgardMulti{
		Slots:   slots,
		Damgard: &Damgard{params},
	}
}

// DamgardMultiSecKey is a secret key for Damgard multi input scheme.
type DamgardMultiSecKey struct {
	Msk []*DamgardSecKey
	Otp data.Matrix
}

// GenerateMasterKeys generates a matrix comprised of master public
// keys and a struct encapsulating master public keys for the scheme.
//
// It returns an error in case master keys could not be generated.
func (dm *DamgardMulti) GenerateMasterKeys() (data.Matrix, *DamgardMultiSecKey, error) {
	multiMsk := make([]*DamgardSecKey, dm.Slots)
	multiMpk := make([]data.Vector, dm.Slots)
	multiOtp := make([]data.Vector, dm.Slots)

	for i := 0; i < dm.Slots; i++ {
		msk, mpk, err := dm.Damgard.GenerateMasterKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("error in master key generation")
		}
		multiMsk[i] = msk
		multiMpk[i] = mpk

		otp, err := data.NewRandomVector(dm.Params.L, sample.NewUniform(dm.Params.Bound))
		if err != nil {
			return nil, nil, fmt.Errorf("error in random vector generation")
		}
		multiOtp[i] = otp
	}

	secKey := &DamgardMultiSecKey{
		Msk: multiMsk,
		Otp: multiOtp,
	}

	return multiMpk, secKey, nil
}

// DamgardMultiDerivedKey is a functional encryption key for DamgardMulti scheme.
type DamgardMultiDerivedKey struct {
	Keys1 data.Vector
	Keys2 data.Vector
	Z     *big.Int // Σ <u_i, y_i> where u_i is OTP key for i-th encryptor
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *DamgardMulti) DeriveKey(secKey *DamgardMultiSecKey, y data.Matrix) (*DamgardMultiDerivedKey, error) {
	if err := y.CheckBound(dm.Params.Bound); err != nil {
		return nil, err
	}

	z, err := secKey.Otp.Dot(y)
	if err != nil {
		return nil, err
	}
	z.Mod(z, dm.Params.Bound)

	derivedKeys1 := make([]*big.Int, dm.Slots)
	derivedKeys2 := make([]*big.Int, dm.Slots)

	for i := 0; i < dm.Slots; i++ {
		//secKeyI := &DamgardSecKey{secKey.msk1[i], secKey.msk2[i]}
		derivedKey, err := dm.Damgard.DeriveKey(secKey.Msk[i], y[i])
		if err != nil {
			return nil, err
		}

		derivedKeys1[i] = derivedKey.Key1
		derivedKeys2[i] = derivedKey.Key2
	}

	return &DamgardMultiDerivedKey{data.NewVector(derivedKeys1), data.NewVector(derivedKeys2), z}, nil
}

// Decrypt accepts the matrix cipher comprised of encrypted vectors,
// functional encryption key, and a matrix y comprised of plaintext vectors.
// It returns the sum of inner products.
// If decryption failed, error is returned.
func (dm *DamgardMulti) Decrypt(cipher data.Matrix, key *DamgardMultiDerivedKey, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(dm.Params.Bound); err != nil {
		return nil, err
	}

	sum := big.NewInt(0)
	for i := 0; i < dm.Slots; i++ {
		keyI := &DamgardDerivedKey{key.Keys1[i], key.Keys2[i]}
		cy, err := dm.Damgard.Decrypt(cipher[i], keyI, y[i])
		if err != nil {
			return nil, err
		}

		sum.Add(sum, cy)
	}

	res := new(big.Int).Sub(sum, key.Z)
	res.Mod(res, dm.Params.Bound)
	return res, nil
}

// DamgardMultiEnc represents a single encryptor for the DamgardMulti scheme.
type DamgardMultiEnc struct {
	*Damgard
}

// NewDamgardMultiEnc takes configuration parameters of an underlying
// Damgard scheme instance, and instantiates a new DamgardMultiEnc.
func NewDamgardMultiEnc(params *DamgardParams) *DamgardMultiEnc {
	return &DamgardMultiEnc{
		Damgard: &Damgard{params},
	}
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key and one-time pad otp (which
// is a part of the secret key). It returns the ciphertext vector.
// If encryption failed, error is returned.
func (e *DamgardMultiEnc) Encrypt(x data.Vector, pubKey, otp data.Vector) (data.Vector, error) {
	if err := x.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	otp = x.Add(otp)
	otpModulo := otp.Mod(e.Params.Bound)

	return e.Damgard.Encrypt(otpModulo, pubKey)
}

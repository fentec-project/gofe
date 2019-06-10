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

package simple

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// DDHDMCFE represents a decentralized DMCFE input variant of the
// underlying DDH scheme based on
// Abdalla, Benhamouda, Kohlweiss,and Waldner:
// "Decentralizing Inner-Product Functional Encryption".
type DDHDMCFEClient struct {
	// number of encryptors
	Idx int
	Slots int
	DDHScheme *DDH
	KeyShare data.Vector
}

// NewDDHDMCFE configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors l (each encryptor encrypts a vector of length l),
// the bit length of the modulus (we are operating in the Z_p
// group), and a bound by which the coordinates of the input
// vectors are bounded.
//
// It returns an error in case the underlying DDH scheme instances could
// not be properly instantiated.
func NewDDHDMCFEClient(slots, ddh *DDH) (*DDHDMCFEClient, error) {
	return &DDHDMCFEClient{
		DDHScheme:   ddh,
	}, nil
}

// SetT sets a secret key for client c, based on the public keys of all the
// clients involved in the scheme. It assumes that Idx of a client indicates
// which is the corresponding public key in pubT.
func (c *DDHDMCFEClient) SetKeyShare(pubT []data.Matrix) error {
	t := data.NewConstantMatrix(2, 2, big.NewInt(0))
	add := data.NewConstantMatrix(2, 2, big.NewInt(0))
	var err error
	for k := 0; k < len(pubT); k++ {
		if k == c.Idx {
			continue
		}
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				add[i][j] = new(big.Int).Exp(pubT[k][i][j], c.TSec[i][j], bn256.Order)
			}
		}
		if k < c.Idx {
			t, err = t.Add(add)
			if err != nil {
				return err
			}
		} else {
			t, err = t.Sub(add)
			if err != nil {
				return err
			}
		}
		t = t.Mod(bn256.Order)
	}
	c.T = t

	return nil
}



// NewDDHDMCFEFromParams takes the number of slots and configuration
// parameters of an existing DDH scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new DDHDMCFE instance.
func NewDDHDMCFEclientFromParams(slots int, params *DDHParams) *DDHDMCFE {
	return &DDHDMCFE{
		Slots: slots,
		DDH:   &DDH{params},
	}
}

// DDHDMCFESecKey is a secret key for DDH DMCFE input scheme.
type DDHDMCFESecKey struct {
	sk    data.Vector
	pk    data.Vector
	OtpKey data.Vector
	KeyShare data.Vector
}

// GenerateMasterKeys generates matrices comprised of master secret
// keys and master public keys for the scheme.
//
// It returns an error in case master keys could not be generated.
func (dm *DDHDMCFEClient) GenerateKeys() (*DDHDMCFESecKey, error) {
	masterSecretKey, masterPublicKey, err := dm.DDHScheme.GenerateMasterKeys()

	if err != nil {
			return nil, fmt.Errorf("error in master key generation")
		}

		otpVector, err := data.NewRandomVector(dm.DDHScheme.Params.L, sample.NewUniform(dm.DDHScheme.Params.Bound))
		if err != nil {
			return nil, fmt.Errorf("error in random vector generation")
		}


	return &DDHDMCFESecKey{sk:       masterSecretKey,
						   pk:       masterPublicKey,
						   OtpKey:   otpVector,
						   KeyShare: dm.KeyShare,}, nil
}

// DDHDMCFEDerivedKey is functional encryption key for DDH Scheme.
type DDHDMCFEDerivedKey struct {
	Keys   data.Vector
	OTPKey *big.Int
}

// DeriveKey takes secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *DDHDMCFEClient) DeriveKeyShare(secKey *DDHDMCFESecKey, y data.Vector) (*DDHDMCFEDerivedKey, error) {
	if err := y.CheckBound(dm.DDHScheme.Params.Bound); err != nil {
		return nil, err
	}

	yPart := data.NewVector(y[(dm.Idx * dm.DDHScheme.Params.L):((dm.Idx + 1) * dm.DDHScheme.Params.L)])
	z1, err := dm.DDHScheme.DeriveKey(secKey.)

			secKey.OtpKey.Dot(yPart)
	if err != nil {
		return nil, err
	}

	z2, err := secKey.KeyShare.Dot(y)
	if err != nil {
		return nil, err
	}

	z.Mod(z, dm.DDHScheme.Params.P)


	for i := 0; i < dm.Slots; i++ {
		derivedKey, err := dm.DDH.DeriveKey(secKey.Msk[i], y[i])
		if err != nil {
			return nil, err
		}

		derivedKeys[i] = derivedKey
	}

	return &DDHDMCFEDerivedKey{data.NewVector(derivedKeys), z}, nil
}

// Decrypt accepts the matrix cipher comprised of encrypted vectors,
// functional encryption key, and a matrix y comprised of plaintext vectors.
// It returns the sum of inner products.
// If decryption failed, error is returned.
func (dm *DDHDMCFE) Decrypt(cipher data.Matrix, key *DDHDMCFEDerivedKey, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(dm.Params.Bound); err != nil {
		return nil, err
	}

	sum := big.NewInt(0)
	for i := 0; i < dm.Slots; i++ {
		c, err := dm.DDH.Decrypt(cipher[i], key.Keys[i], y[i])
		if err != nil {
			return nil, err
		}

		sum.Add(sum, c)
	}

	res := new(big.Int).Sub(sum, key.OTPKey)
	res.Mod(res, dm.Params.Bound)
	return res, nil
}

// DDHDMCFEEnc represents a single encryptor for the DDHDMCFE scheme.
type DDHDMCFEEnc struct {
	*DDH
}

// NewDDHDMCFEEnc takes configuration parameters of an underlying
// DDH scheme instance, and instantiates a new DDHDMCFEEnc.
func NewDDHDMCFEEnc(params *DDHParams) *DDHDMCFEEnc {
	return &DDHDMCFEEnc{
		DDH: &DDH{params},
	}
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key and one-time pad otp (which
// is a part of the secret key). It returns the ciphertext vector.
// If encryption failed, error is returned.
func (e *DDHDMCFEEnc) Encrypt(x data.Vector, pubKey, otp data.Vector) (data.Vector, error) {
	if err := x.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	otp = x.Add(otp)
	otpModulo := otp.Mod(e.Params.Bound)

	return e.DDH.Encrypt(otpModulo, pubKey)
}

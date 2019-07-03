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
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// DamgardMultiClient represents a client in a decentralized
// multi client variant of the underlying multi client (dmagard_multi)
// scheme based. The decentralization is based on
// Abdalla, Benhamouda, Kohlweiss,and Waldner:
// "Decentralizing Inner-Product Functional Encryption".
// The participants in the scheme are clients without a central authority.
// They interactively generate private keys for each client so that client i
// can encrypt vector x_i. The scheme allows the clients to interactively
// generate a key_Y, depending on a matrix Y with rows y_i, so that
// given key_y and the ciphertext the decryptor can compute value
// Σ_i <x_i, y_i> (sum of dot products).
type DamgardDecMultiClient struct {
	// number of encryptors
	Idx           int
	*DamgardMulti
	ClientPubKey  *big.Int
	ClientSecKey  *big.Int
	Share         data.Matrix
}

// NewDamgardDecMultiClient configures a new client in the decentralized scheme
// based on a underlying DamgardMulti scheme.
// It accepts the identification of the client (an integer from [0, numClients))
// and the underlying DamgardMulti scheme (which contains all the shared parameters)
//
// It returns an error in case the scheme cannot be properly initialized.
func NewDamgardDecMultiClient(idx int, damgardMulti *DamgardMulti) (*DamgardDecMultiClient, error) {
	sampler := sample.NewUniform(damgardMulti.Params.Q)
	sec, err := sampler.Sample()
	if err != nil {
		return nil, fmt.Errorf("could not generate random value")
	}
	pub := new(big.Int).Exp(damgardMulti.Params.G, sec, damgardMulti.Params.P)

	return &DamgardDecMultiClient{
		Idx:           idx,
		DamgardMulti:  damgardMulti,
		ClientPubKey:  pub,
		ClientSecKey:  sec,
	}, nil
}

// SetShare sets a shared key for client c, based on the public keys of all the
// clients involved in the scheme. It assumes that Idx of a client indicates
// which is the corresponding public key in pubKeys. Shared keys are such that
// each client has a random key but all the shared keys sum to 0.
func (c *DamgardDecMultiClient) SetShare(pubKeys []*big.Int) error {
	c.Share = data.NewConstantMatrix(c.NumClients, c.Params.L, big.NewInt(0))
	var add data.Matrix
	var err error
	for k := 0; k < len(pubKeys); k++ {
		if k == c.Idx {
			continue
		}
		sharedNum := new(big.Int).Exp(pubKeys[k], c.ClientSecKey, c.Params.P)
		sharedKey := sha256.New().Sum([]byte(sharedNum.String()))
		var sharedKeyFixed [32]byte
		copy(sharedKeyFixed[:], sharedKey)

		add, err = data.NewRandomDetMatrix(c.NumClients, c.Params.L, c.Params.Q, &sharedKeyFixed)
		if err != nil {
			return err
		}

		if k < c.Idx {
			c.Share, err = c.Share.Add(add)
			if err != nil {
				return err
			}
		} else {
			c.Share, err = c.Share.Sub(add)
			if err != nil {
				return err
			}
		}
		c.Share = c.Share.Mod(c.Params.Q)
	}

	return nil
}

// DamgardDecMultiSecKey is a secret key that each client has.
type DamgardDecMultiSecKey struct {
	sk     *DamgardSecKey
	pk     data.Vector
	OtpKey data.Vector
}

// GenerateKeys generates the secret key for each client.
//
// It returns an error in case master keys could not be generated.
func (c *DamgardDecMultiClient) GenerateKeys() (*DamgardDecMultiSecKey, error) {
	masterSecretKey, masterPublicKey, err := c.Damgard.GenerateMasterKeys()

	if err != nil {
		return nil, fmt.Errorf("error in master key generation")
	}

	otpVector, err := data.NewRandomVector(c.Damgard.Params.L,
		sample.NewUniform(c.Damgard.Params.Q))
	if err != nil {
		return nil, fmt.Errorf("error in random vector generation")
	}

	return &DamgardDecMultiSecKey{sk: masterSecretKey,
		pk:     masterPublicKey,
		OtpKey: otpVector}, nil
}

// Encrypt generates a ciphertext from the input vector x
// with the provided secret key.
// If encryption failed, error is returned.
func (c *DamgardDecMultiClient) Encrypt(x data.Vector, key *DamgardDecMultiSecKey) (data.Vector, error) {
	if err := x.CheckBound(c.Params.Bound); err != nil {
		return nil, err
	}

	xAddOtp := x.Add(key.OtpKey)
	otpModulo := xAddOtp.Mod(c.Params.Q)

	return c.Damgard.Encrypt(otpModulo, key.pk)
}

// DamgardDecMultiDerivedKey is functional encryption key for decentralized
// Damgrad Scheme.
type DamgardDecMultiDerivedKeyPart struct {
	KeyPart    *DamgardDerivedKey
	OTPKeyPart *big.Int
}

// DeriveKeyShare is run by a client. It takes a secret key and
// a matrix y comprised of input vectors, and returns a part of
// the functional encryption key.
// In case the key could not be derived, it returns an error.
func (c *DamgardDecMultiClient) DeriveKeyShare(secKey *DamgardDecMultiSecKey, y data.Matrix) (*DamgardDecMultiDerivedKeyPart, error) {
	if err := y.CheckBound(c.Damgard.Params.Bound); err != nil {
		return nil, err
	}

	yPart := data.NewVector(y[c.Idx])
	z1, err := secKey.OtpKey.Dot(yPart)
	if err != nil {
		return nil, err
	}

	z2, err := c.Share.Dot(y)
	if err != nil {
		return nil, err
	}

	zPart := new(big.Int).Add(z1, z2)
	zPart.Mod(zPart, c.Damgard.Params.Q)
	key, err := c.Damgard.DeriveKey(secKey.sk, yPart)
	if err != nil {
		return nil, err
	}

	return &DamgardDecMultiDerivedKeyPart{key, zPart}, nil
}

// DamgardDecMultiDec represents a decryptor for the decentralized variant of the
// underlying multi input Damgard scheme.
type DamgardDecMultiDec struct {
	*DamgardMulti
}

// NewDamgardDecMultiDec takes the underlying DamgardMulti and instantiates a
// new DamgardDecMultiDec struct.
func NewDamgardDecMultiDec(damgardMulti *DamgardMulti) *DamgardDecMultiDec {
	return &DamgardDecMultiDec{
		DamgardMulti: NewDamgardMultiFromParams(damgardMulti.NumClients, damgardMulti.Bound, damgardMulti.Params),
	}
}

// Decrypt accepts an array of ciphertexts comprised of encrypted vectors,
// an array of partial functional encryption keys, and a matrix y representing
// the inner-product vectors. It returns the sum of inner products.
// If decryption failed, an error is returned.
func (dc *DamgardDecMultiDec) Decrypt(cipher []data.Vector, partKeys []*DamgardDecMultiDerivedKeyPart, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(dc.Params.Bound); err != nil {
		return nil, err
	}
	if len(cipher) != len(partKeys) {
		return nil, fmt.Errorf("the number of keys does not match the number of ciphertexts")
	}

	keys := make([]*DamgardDerivedKey, len(partKeys))
	z := big.NewInt(0)
	for i := 0; i < len(partKeys); i++ {
		z.Add(z, partKeys[i].OTPKeyPart)
		keys[i] = partKeys[i].KeyPart
	}
	z.Mod(z, dc.Params.Q)
	key := &DamgardMultiDerivedKey{Keys: keys,
		Z: z,
	}

	return dc.DamgardMulti.Decrypt(cipher, key, y)
}

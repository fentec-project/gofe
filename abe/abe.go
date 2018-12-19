package abe

import (
	"fmt"
	"math/big"

	"strconv"
	"strings"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// ABEParams represents configuration parameters for the ABE scheme instance.
type abeParams struct {
	L int      // number of attributes
	P *big.Int // order of the elliptic curve
}

// ABE represents an ABE scheme.
type ABE struct {
	Params *abeParams
}

// NewABE configures a new instance of the scheme.
// It accepts l the number of attributes possibly used in
// the scheme. Attributes' names will be considered as
// elements of a set {0, 1,..., l-1}.
func NewABE(l int) *ABE {
	return &ABE{Params: &abeParams{
		L: l, // number of attributes in the whole universe
		P: bn256.Order,
	}}
}

// ABEPubKey represents a public key of an ABE scheme.
type ABEPubKey struct {
	t data.VectorG2
	y *bn256.GT
}

// GenerateMasterKeys generates a new set of public keys, needed
// for encrypting data, and secret keys needed for generating keys
// for decryption.
func (a *ABE) GenerateMasterKeys() (*ABEPubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.P)
	sk, err := data.NewRandomVector(a.Params.L+1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk[:a.Params.L].MulG2()
	y := new(bn256.GT).ScalarBaseMult(sk[a.Params.L])

	return &ABEPubKey{t: t, y: y}, sk, nil
}

// ABECipher represents a ciphertext of an ABE scheme.
type ABECipher struct {
	gamma     []int         // the set of attributes that can be used for policy of decryption
	attribToI map[int]int   // a map that connects the attributes in gamma with elements of e
	e0        *bn256.GT     // the first part of the encryption
	e         data.VectorG2 // the second part of the encryption
}

// Encrypt takes as an input a message msg represented as an element of pairing
// group G_T, gamma a set of attributes that can be latter used to in the decryption policy
// and a public key pk. It returns an encryption of msk. In case of a failed procedure
// an error is returned.
func (a *ABE) Encrypt(msg *bn256.GT, gamma []int, pk *ABEPubKey) (*ABECipher, error) {
	sampler := sample.NewUniform(a.Params.P)
	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	e0 := new(bn256.GT).Add(msg, new(bn256.GT).ScalarMult(pk.y, s))
	e := make(data.VectorG2, len(gamma))
	attribToI := make(map[int]int)
	for i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.t[el], s)
		attribToI[el] = i
	}

	return &ABECipher{gamma: gamma,
		attribToI: attribToI,
		e0:        e0,
		e:         e}, nil
}

// MSP represents a monotone span program (MSP) describing a policy defining which
// attributes are needed to decrypt the ciphertext. It includes a matrix
// mat and a mapping from the rows of the mat to attributes. A MSP policy
// allows decryption of an entity with a set of attributes A if an only if all the
// rows of the matrix mapped to an element of A span the vector [1, 1,..., 1]
// in Z_p.
type MSP struct {
	P           *big.Int
	Mat         data.Matrix
	RowToAttrib []int
}

// GeneratePolicyKeys given a monotone span program (MSP) msp and the vector of secret
// keys produces a vector of keys needed for the decryption. In particular,
// for each row of the MSP matrix msp.mat it creates a corresponding key. Since
// each row of msp.mat has a corresponding key, this keys can be latter delegated
// to entities with corresponding attributes.
func (a *ABE) GeneratePolicyKeys(msp *MSP, sk data.Vector) (data.VectorG1, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	if len(sk) != (a.Params.L + 1) {
		return nil, fmt.Errorf("the secret key has wrong length")
	}

	u, err := getSum(sk[a.Params.L], a.Params.P, len(msp.Mat[0]))
	if err != nil {
		return nil, err
	}

	key := make(data.VectorG1, len(msp.Mat))
	for i := 0; i < len(msp.Mat); i++ {
		if 0 > msp.RowToAttrib[i] || a.Params.L <= msp.RowToAttrib[i] {
			return nil, fmt.Errorf("attributes of msp not in the universe of a")
		}

		tMapIInv := new(big.Int).ModInverse(sk[msp.RowToAttrib[i]], a.Params.P)
		matTimesU, err := msp.Mat[i].Dot(u)
		if err != nil {
			return nil, err
		}
		pow := new(big.Int).Mul(tMapIInv, matTimesU)
		key[i] = new(bn256.G1).ScalarBaseMult(pow)
	}

	return key, nil
}

// getSum is a helping function that given integers y, p and d generates a
// random d dimesional vector over Z_p whose entries sum to y in Z_p.
func getSum(y *big.Int, p *big.Int, d int) (data.Vector, error) {
	sampler := sample.NewUniform(p)
	ret, err := data.NewRandomVector(d, sampler)
	if err != nil {
		return nil, err
	}
	sum := big.NewInt(0)
	for i := 0; i < d-1; i++ {
		sum.Add(sum, ret[i])
		sum.Mod(sum, p)
	}
	ret[d-1] = new(big.Int).Sub(y, sum)
	ret[d-1].Mod(ret[d-1], p)

	return ret, nil
}

// ABEKey represents a key structure for decrypting a ciphertext. It includes
// mat a matrix, d a set of vectors and rowToAttib a mapping from rows of mat
// (or entries of d) to corresponding attributes. Vector d is a set of keys
// that can decrypt a ciphertext of the rows of mat span the vector [1, 1,..., 1].
type ABEKey struct {
	mat         data.Matrix
	d           data.VectorG1
	rowToAttrib []int
}

// DelegateKeys given the set of all keys produced from the MSP struct msp joins
// those that correspond to attributes appearing in attrib and creates an ABEKey
// for the decryption.
func (a *ABE) DelegateKeys(keys data.VectorG1, msp *MSP, attrib []int) *ABEKey {
	attribMap := make(map[int]bool)
	for _, e := range attrib {
		attribMap[e] = true
	}
	mat := make([]data.Vector, 0)
	d := make(data.VectorG1, 0)
	rowToAttrib := make([]int, 0)
	for i := 0; i < len(msp.Mat); i++ {
		if attribMap[msp.RowToAttrib[i]] {
			mat = append(mat, msp.Mat[i])
			d = append(d, keys[i])
			rowToAttrib = append(rowToAttrib, msp.RowToAttrib[i])
		}
	}

	return &ABEKey{mat: mat,
		d:           d,
		rowToAttrib: rowToAttrib}
}

// Decrypt takes as an input a cipher and an ABEKey key and tries to decrypt
// the cipher. If the ABEKey is properly generated, this is possible if and only
// if the rows of the matrix in the key span the vector [1, 1,..., 1]. If this
// is not possible, an error is returned.
func (a *ABE) Decrypt(cipher *ABECipher, key *ABEKey) (*bn256.GT, error) {
	// get a combination alpha of keys needed to decrypt
	ones := data.NewConstantVector(len(key.mat[0]), big.NewInt(1))
	alpha, err := gaussianElimination(key.mat.Transpose(), ones, a.Params.P)
	if err != nil {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}

	ret := new(bn256.GT).Set(cipher.e0)
	for i := 0; i < len(alpha); i++ {
		pair := bn256.Pair(key.d[i], cipher.e[cipher.attribToI[key.rowToAttrib[i]]])
		pair.ScalarMult(pair, alpha[i])
		pair.Neg(pair)
		ret.Add(ret, pair)
	}

	return ret, nil
}

// BooleanToMSP takes as an input a boolean expression (without a NOT gate) and
// outputs a msp structure representing the expression, i.e. a matrix whose rows
// correspond to attributes used in the expression and with the property that a
// boolean expression assigning 1 to some attributes is satisfied iff the
// corresponding rows span a vector [1, 1,..., 1] or vector [1, 0,..., 0] in Z_p
// depending if parameter convertToOnes is set to true or false. Additionally a
// vector is produced whose i-th entry indicates to which attribute the i-th row
// corresponds.
func BooleanToMSP(boolExp string, p *big.Int, convertToOnes bool) (*MSP, error) {
	// by the Lewko-Waters algorithm we obtain a MSP struct with the property
	// that is the the boolean expression is satisfied if and only if the corresponding
	// rows of the msp matrix span the vector [1, 0,..., 0] in Z_p
	vec := make(data.Vector, 1)
	vec[0] = big.NewInt(1)
	msp, _, err := booleanToMSPIterative(boolExp, vec, 1)
	if err != nil {
		return nil, err
	}
	msp.P = p

	// if convertToOnes is set to true convert the matrix to such a MSP
	// struct so that the boolean expression is satisfied iff the
	// corresponding rows span the vector [1, 1,..., 1] in Z_p
	if convertToOnes {
		// create an invertible matrix that maps [1, 0,..., 0] to [1,1,...,1]
		perm := make(data.Matrix, len(msp.Mat[0]))
		for i := 0; i < len(msp.Mat[0]); i++ {
			perm[i] = make(data.Vector, len(msp.Mat[0]))
			for j := 0; j < len(msp.Mat[0]); j++ {
				if i == 0 || j == i {
					perm[i][j] = big.NewInt(1)
				} else {
					perm[i][j] = big.NewInt(0)
				}

			}
		}
		//change the msp matrix by multiplying with it the permutation matrix
		msp.Mat, err = msp.Mat.Mul(perm)
		if err != nil {
			return nil, err
		}
	}
	msp.Mat = msp.Mat.Mod(p)

	return msp, nil
}

// booleanToMspIterative iteratively builds a msp structure by splitting the expression
// into two parts separated by an AND or OR gate, generating a msp structure on each of
// them, and joining both structures together. The structure is such the the boolean expression
// assigning 1 to some attributes is satisfied iff the corresponding rows span a vector
// [1, 0,..., 0]. The algorithm is known as Lewko-Waters algorithm, see Appendix G in
// https://eprint.iacr.org/2010/351.pdf.
func booleanToMSPIterative(boolExp string, vec data.Vector, c int) (*MSP, int, error) {
	boolExp = strings.TrimSpace(boolExp)
	numBrc := 0
	var boolExp1 string
	var boolExp2 string
	var c1 int
	var cOut int
	var msp1 *MSP
	var msp2 *MSP
	var err error
	found := false

	// find the main AND or OR gate and iteratively call the function on
	// both the sub-expressions
	for i, e := range boolExp {
		if e == '(' {
			numBrc++
			continue
		}
		if e == ')' {
			numBrc--
			continue
		}
		if numBrc == 0 && i < len(boolExp)-3 && boolExp[i:i+3] == "AND" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+3:]
			vec1, vec2 := makeAndVecs(vec, c)
			msp1, c1, err = booleanToMSPIterative(boolExp1, vec1, c+1)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMSPIterative(boolExp2, vec2, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
		if numBrc == 0 && i < len(boolExp)-2 && boolExp[i:i+2] == "OR" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+2:]
			msp1, c1, err = booleanToMSPIterative(boolExp1, vec, c)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMSPIterative(boolExp2, vec, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
	}

	// If the AND or OR gate is not found then there are two options,
	// either the whole expression is in brackets, or the the expression
	// is only one attribute. It neither of both is true, then
	// an error is returned while converting the expression into an
	// attribute
	if found == false {
		if boolExp[0] == '(' && boolExp[len(boolExp)-1] == ')' {
			boolExp = boolExp[1:(len(boolExp) - 1)]
			return booleanToMSPIterative(boolExp, vec, c)
		}

		attrib, err := strconv.Atoi(boolExp)
		if err != nil {
			return nil, 0, err
		}
		mat := make(data.Matrix, 1)
		mat[0] = make(data.Vector, c)
		for i := 0; i < c; i++ {
			if i < len(vec) {
				mat[0][i] = new(big.Int).Set(vec[i])
			} else {
				mat[0][i] = big.NewInt(0)
			}
		}

		rowToAttrib := make([]int, 1)
		rowToAttrib[0] = attrib
		return &MSP{Mat: mat, RowToAttrib: rowToAttrib}, c, nil
	} else {
		// otherwise we join the two msp structures into one
		mat := make(data.Matrix, len(msp1.Mat)+len(msp2.Mat))
		for i := 0; i < len(msp1.Mat); i++ {
			mat[i] = make(data.Vector, cOut)
			for j := 0; j < len(msp1.Mat[0]); j++ {
				mat[i][j] = msp1.Mat[i][j]
			}
			for j := len(msp1.Mat[0]); j < cOut; j++ {
				mat[i][j] = big.NewInt(0)
			}
		}
		for i := 0; i < len(msp2.Mat); i++ {
			mat[i+len(msp1.Mat)] = msp2.Mat[i]
		}
		rowToAttrib := append(msp1.RowToAttrib, msp2.RowToAttrib...)

		return &MSP{Mat: mat, RowToAttrib: rowToAttrib}, cOut, nil
	}
}

// makeAndVecs is a helping structure that given a vector and and counter
// creates two new vectors used whenever an AND gate is found in a iterative
// step of BooleanToMsp
func makeAndVecs(vec data.Vector, c int) (data.Vector, data.Vector) {
	vec1 := data.NewConstantVector(c+1, big.NewInt(0))
	vec2 := data.NewConstantVector(c+1, big.NewInt(0))
	for i := 0; i < len(vec); i++ {
		vec2[i].Set(vec[i])
	}
	vec1[c] = big.NewInt(-1)
	vec2[c] = big.NewInt(1)

	return vec1, vec2
}

// gaussianElimination solves a vector equation mat * x = v and finds vector x,
// using Gaussian elimination. Arithmetic operations are considered to be over
// Z_p, where p should be a prime number. If such x does not exist, then the
// function returns an error.
func gaussianElimination(mat data.Matrix, v data.Vector, p *big.Int) (data.Vector, error) {
	if len(mat) == 0 || len(mat[0]) == 0 {
		return nil, fmt.Errorf("the matrix should not be empty")
	}
	if len(mat) != len(v) {
		return nil, fmt.Errorf(fmt.Sprintf("dimensions should match: "+
			"rows of the matrix %d, length of the vector %d", len(mat), len(v)))
	}

	// we copy matrix mat into m and v into u
	cpMat := make([]data.Vector, len(mat))
	u := make(data.Vector, len(mat))
	for i := 0; i < len(mat); i++ {
		cpMat[i] = make(data.Vector, len(mat[0]))
		for j := 0; j < len(mat[0]); j++ {
			cpMat[i][j] = new(big.Int).Set(mat[i][j])
		}
		u[i] = new(big.Int).Set(v[i])
	}
	m, _ := data.NewMatrix(cpMat) // error is impossible to happen

	// m and u are transformed to be in the upper triangular form
	ret := make(data.Vector, len(mat[0]))
	h, k := 0, 0
	for h < len(m) && k < len(m[0]) {
		zero := true
		for i := h; i < len(m); i++ {
			if m[i][k].Sign() != 0 {
				m[h], m[i] = m[i], m[h]

				u[h], u[i] = u[i], u[h]
				zero = false
				break
			}
		}
		if zero {
			ret[k] = big.NewInt(0)
			k++
			continue
		}
		mHKInv := new(big.Int).ModInverse(m[h][k], p)
		for i := h + 1; i < len(m); i++ {
			f := new(big.Int).Mul(mHKInv, m[i][k])
			m[i][k] = big.NewInt(0)
			for j := k + 1; j < len(m[0]); j++ {
				m[i][j].Sub(m[i][j], new(big.Int).Mul(f, m[h][j]))
				m[i][j].Mod(m[i][j], p)
			}
			u[i].Sub(u[i], new(big.Int).Mul(f, u[h]))
			u[i].Mod(u[i], p)
		}
		k++
		h++
	}

	for i := h; i < len(m); i++ {
		if u[i].Sign() != 0 {
			return nil, fmt.Errorf("no solution")
		}
	}
	for j := k; j < len(m[0]); j++ {
		ret[j] = big.NewInt(0)
	}

	// use the upper triangular form to obtain the solution
	for i := h - 1; i >= 0; i-- {
		for j := k - 1; j >= 0; j-- {
			if ret[j] == nil {
				tmpSum, _ := m[i][j+1:].Dot(ret[j+1:])
				ret[j] = new(big.Int).Sub(u[i], tmpSum)
				mHKInv := new(big.Int).ModInverse(m[i][j], p)
				ret[j].Mul(ret[j], mHKInv)
				ret[j].Mod(ret[j], p)
				break
			}
		}
	}

	return ret, nil
}

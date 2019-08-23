package abe_test

import (
"testing"

	"math/big"
	"fmt"

	"github.com/fentec-project/bn256"
)

func TestBN(t *testing.T) {
	hashed := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	hashed2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	fmt.Println(hashed)

	twice1 := new(bn256.G2).Add(hashed, hashed2)
	fmt.Println("tw", twice1)

	//hashed = new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	//fmt.Println(hashed)

	fmt.Println(hashed)

	twice2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	twice2.Add(twice2, hashed)
	twice2.ScalarBaseMult(big.NewInt(1))


	fmt.Println(twice2)
	fmt.Println(hashed)

	twice2.Add(hashed, twice2)

	fmt.Println("tw", twice2)

	fmt.Println(twice1.String() == twice2.String())

	//hashed.Neg(hashed)
	//twice = new(bn256.G2).Add(hashed, hashed)
	//fmt.Println("neg", twice)
	//
	//twice = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	//twice.Add(twice, hashed)
	//twice.Add(twice, hashed)
	//fmt.Println("neg", twice)
}
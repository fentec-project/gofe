# GoFE - Functional Encryption library [![Build Status](https://travis-ci.org/fentec-project/gofe.svg?branch=master)](https://travis-ci.org/fentec-project/gofe) [![GoDoc](https://godoc.org/github.com/fentec-project/gofe?status.svg)](https://godoc.org/github.com/fentec-project/gofe)

GoFE is a cryptographic library offering different state-of-the-art
implementations of functional encryption schemes, specifically FE
schemes for _linear_ (e.g. _inner products_) and _quadratic polynomials_.

To quickly get familiar with FE, read a short and very high-level 
introduction on our [Introductory Wiki page](../../wiki/Introduction-to-FE).

<!-- toc -->
- [Building GoFE](#building-gofe)
- [Using GoFE in your project](#using-gofe-in-your-project)
    * [Select the FE scheme](#1.-select-the-fe-scheme)
    * [Configure selected scheme](#2.-configure-selected-scheme)
    * [Prepare input data](#3.-prepare-input-data)
    * [Use the scheme (examples)](#4.-use-the-scheme-(examples))
<!-- tocstop -->

### Before using the library
Please note that the library is a work in progress and has not yet
reached a stable release. Code organization and APIs are **not stable**.
You can expect them to change at any point.

The purpose of GoFE is to support research and proof-of-concept
implementations. It **should not be used in production**.

## Building GoFE
First, download and build the library by running
 `go get -u -t github.com/fentec-project/gofe` from the terminal. 
 
To make sure the library works as expected, navigate to your `$GOPATH/src/github.com/fentec-project/gofe` 
directory and run `go test -v ./...` . 

## Using GoFE in your project
After you have successfuly built the library, you can use it in your project.
Instructions below provide a brief introduction to the most important parts
of the library, and guide you through a sequence of steps that will quickly
get your FE example up and running.  

### Select the FE scheme
You can choose from the following  set of schemes:

#### Inner product schemes
You will need to import packages from `ìnnerprod` directory.

We organized implementations in two categories based on their security 
assumptions:
* Scheme with **selective security under chosen-plaintext 
attacks** (s-IND-CPA security) by _Abdalla et. al._ ([paper](https://eprint.iacr.org/2015/017.pdf)).
 The scheme is implemented in various flavors,
    you will find them in the `simple` package:
    * Instantiated from DDH: `DDH` (and its multi input version
     `DDHMulti`).
    * Instanted from LWE: `LWE` and the more performant`RingLWE`.
* Scheme with **adaptive security under chosen-plaintext attacks** (IND-CPA
security) by _Agrawal, Libert and Stehlé_ ([paper](https://eprint.iacr.org/2015/608.pdf)).
Again, there are
 different implementations of the scheme, you will find them in
  the `fullysec` (meaning "fully secure") package:
    * Instanted from DDH: `Damgard` (and its multi input
     version `DamgardMulti`). This scheme is similar to `simple.DDH`
       scheme but uses one more group element to achieve full security,
       similar to how Damgård's encryption scheme is obtained from ElGamal
       scheme ([paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_36)).
    * Instanted from LWE: `LWE`.

You can see that two scheme instances (`DDHMulti` and `DamgardMulti`) are
implemented for multiple inputs as well as for single input. Both are
built on the work of _Abdalla et.al_ ([paper](https://eprint.iacr.org/2017/972.pdf)).
Currently the rest of scheme instances only support single input.

#### Quadratic polynomial schemes
You will need `SGP` scheme from package `quadratic`. 

It contains 
implementation of efficient FE scheme for **quadratic multi-variate
polynomials** by _Sans, Gay_ and _Pointcheval_ 
([paper](https://eprint.iacr.org/2018/206.pdf)) which is based on
bilinear pairings, and offers adaptive security under chosen-plaintext
attacks (IND-CPA security).

### Configure selected scheme
All GoFE schemes are implemented as Go structs with (at least logically)
similar APIs. So the first thing we need to do is to create a scheme instance
by instantiating the appropriate struct. For this step, we need to pass in 
some configuration, e.g. values of parameters for the selected scheme.

Let's say we selected a `simple.DDH` scheme. We create a new scheme instance with:
````go
scheme, _ := simple.NewDDH(5, 128, big.NewInt(1000))
````

In the line above, the first argument is length of input vectors **x**
and **y**, the second argument is bit length of prime modulus _p_
(because this particular scheme operates in the &#8484;<sub>p</sub> group), and
the last argument represents the upper bound for elements of input vectors.

However, configuration parameters for different FE schemes vary quite a bit.
Please refer to [library documentation](https://godoc.org/github.com/fentec-project/gofe) regarding the meaning of parameters for
 specific schemes. For now, examples and reasonable defaults can be found in 
 the test code. 
 
After you successfully created a FE scheme instance, you can call its
 methods for:
* generation of (secret and public) master keys,
* derivation of functional encryption key,
* encryption, and
* decryption. 

### Prepare input data
#### Vectors and matrices
All GoFE chemes rely on vectors (or matrices) of big integer (`*big.Int`) 
components. 

GoFE schemes use the library's own `Vector` and `Matrix` types. They are implemented
 in the `data` package. A `Vector` is basically a wrapper around `[]*big.Int`
slice, while a `Matrix` wraps a slice of `Vector`s.

In general, you only have to worry about providing input data (usually
vectors **x** and **y**). If you already have your slice of `*big.Int`s 
defined, you can create a `Vector` by calling
`data.NewVector` function with your slice as argument, for example:
````go
// Let's say you already have your data defined in a slice of *big.Ints
x := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
xVec := data.NewVector(x)
````

Similarly, for matrices, you will first have to construct your slice of 
`Vector`s, and pass it to `data.NewMatrix` function: 
````go
vecs := make([]data.Vector, 3) // a slice of 3 vectors
// fill vecs
vecs[0] := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
vecs[1] := []*big.Int{big.NewInt(2), big.NewInt(1), big.NewInt(0)}
vecs[2] := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
xMat := data.NewMatrix(vecs)
````

#### Random data
To generate random `*big.Int` values from different probability distributions,
you can use one of our several implementations of random samplers. The samplers
are provided in the `sample` package and all implement `sample.Sampler`
 interface.
 
You can quickly construct random vectors and matrices by:
1. Configuring the sampler of your choice, for example:
    ````go
    s := sample.NewUniform(big.NewInt(100)) // will sample uniformly from [0,100)
    ````
2. Providing it as an argument to`data.NewRandomVector` or `data.NewRandomMatrix` functions. 
    ````go
    x, _ := data.NewRandomVector(5, s) // creates a random vector with 5 elements
    X, _ := data.NewRandomMatrix(2, 3, s) // creates a random 2x3 matrix
    ````
    
## Use the scheme (examples)
Please note that all the examples below omit error management.

##### Using a single input scheme
The example below demonstrates how to use single input scheme instances.
Although the example shows how to use the`DDH` from package 
`simple`, the usage is similar for all single input schemes, regardless
of their security properties (s-IND-CPA or IND-CPA) and instantiation
 (DDH or LWE).
 
You will see that three `DDH` structs are instantiated to simulate the
 real-world scenarios where each of the three entities involved in FE
 are on separate machines.
 
```go
// Instantiation of a trusted entity that
// will generate master keys and FE key
l := 2 // length of input vectors
bound := big.NewInt(10) // upper bound for input vector coordinates
modulusLength := 128 // bit length of prime modulus p 
trustedEnt, _ := simple.NewDDH(l, modulusLength, bound)
msk, mpk, _ := trustedEnt.GenerateMasterKeys()

y := data.NewVector([]*big.Int{big.NewInt(1), big.NewInt(2)})
feKey, _ := trustedEnt.DeriveKey(msk, y)

// Simulate instantiation of encryptor 
// Encryptor wants to hide x and should be given
// master public key by the trusted entity
enc := simple.NewDDHFromParams(trustedEnt.Params)
x := data.NewVector([]*big.Int{big.NewInt(3), big.NewInt(4)})
cipher, _ := enc.Encrypt(x, mpk)

// Simulate instantiation of decryptor that decrypts the cipher 
// generated by encryptor.
dec := simple.NewDDHFromParams(trustedEnt.Params)
// decrypt to obtain the result: inner prod of x and y
// we expect xy to be 11 (e.g. <[1,2],[3,4]>)
xy, _ := dec.Decrypt(cipher, feKey, y)
```

##### Using a multi input scheme
This example demonstrates how multi input FE schemes can be used.
 
 Here we assume
 that there are `slots` encryptors (e<sub>i</sub>), each with their corresponding
 input vector x<sub>i</sub>. A trusted entity generates all the master keys needed
 for encryption and distributes appropriate keys to appropriate encryptor. Then, 
 encryptor e<sub>i</sub> uses their keys to encrypt their data x<sub>i</sub>.
 The decryptor collects ciphers from all the encryptors. It then relies on the trusted
  entity to derive a decryption key based on its own set of vectors y<sub>i</sub>. With the
  derived key, the decryptor is able to compute the result - inner product
over all vectors, as _Σ <x<sub>i</sub>,y<sub>i</sub>>._

```go
slots := 2                // number of encryptors
l := 3                    // length of input vectors
bound := big.NewInt(1000) // upper bound for input vectors

// Simulate collection of input data.
// X and Y represent matrices of input vectors, where X are collected
// from slots encryptors (ommitted), and Y is only known by a single decryptor.
// Encryptor i only knows its own input vector X[i].
sampler := sample.NewUniform(bound)
X, _ := data.NewRandomMatrix(slots, l, sampler)
Y, _ := data.NewRandomMatrix(slots, l, sampler)

// Trusted entity instantiates scheme instance and generates
// master keys for all the encryptors. It also derives the FE
// key derivedKey for the decryptor.
modulusLength := 64
multiDDH, _ := simple.NewDDHMulti(slots, l, modulusLength, bound)
pubKey, secKey, _ := multiDDH.GenerateMasterKeys()
derivedKey, _ := multiDDH.DeriveKey(secKey, Y)

// Different encryptors may reside on different machines.
// We simulate this with the for loop below, where slots
// encryptors are generated.
encryptors := make([]*simple.DDHMultiEnc, slots)
for i := 0; i < slots; i++ {
    encryptors[i] = simple.NewDDHMultiEnc(multiDDH.Params)
}
// Each encryptor encrypts its own input vector X[i] with the
// keys given to it by the trusted entity.
ciphers := make([]data.Vector, slots)
for i := 0; i < slots; i++ {
    cipher, _ := encryptors[i].Encrypt(X[i], pubKey[i], secKey.OtpKey[i])
    ciphers[i] = cipher
}

// Ciphers are collected by decryptor, who then computes
// inner product over vectors from all encryptors.
decryptor := simple.NewDDHMultiFromParams(slots, multiDDH.Params)
prod, _ = decryptor.Decrypt(ciphers, derivedKey, Y)
```
Note that above we instantiate multiple encryptors - in reality,
 different encryptors will be instantiated on different machines. 
 

##### Using quadratic polynomial scheme
In the example below, we omit instantiation of three different entities
(trusted entity, encryptor and decryptor).
```go
n := 2 // length of input vectors
bound := big.NewInt(10) // Upper bound for coordinates of vectors x, y, and matrix F

// Here we fill our vectors and the matrix F (that represents the
// quadratic function) with random data from [0, bound).
sampler := sample.NewUniform(bound)
F, _ := data.NewRandomMatrix(n, n, sampler)
x, _ := data.NewRandomVector(n, sampler)
y, _ := data.NewRandomVector(n, sampler)

sgp := quadratic.NewSGP(n, bound)     // Create scheme instance
msk, _ := sgp.GenerateMasterKey()     // Create master secret key
cipher, _ := sgp.Encrypt(x, y, msk)   // Encrypt input vectors x, y with secret key
key, _ := sgp.DeriveKey(msk, F)       // Derive FE key for decryption
dec, _ := sgp.Decrypt(cipher, key, F) // Decrypt the result to obtain x^T * F * y
```

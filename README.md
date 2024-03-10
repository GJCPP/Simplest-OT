# Simplest OT protocol
A naive implementation of the simplest OT protocol (the paper below).
```
@inproceedings{chou2015simplest,
    title={The simplest protocol for oblivious transfer},
    author={Chou, Tung and Orlandi, Claudio},
    booktitle={Progress in Cryptology--LATINCRYPT 2015: 4th International Conference on Cryptology and Information Security in Latin America, Guadalajara, Mexico, August 23-26, 2015, Proceedings 4},
    pages={40--58},
    year={2015},
    organization={Springer}
}
```

## Requirement

Implement with [Libsodium](https://doc.libsodium.org/) version=1.0.19-stable

## Implementation

Use the elliptic curve cryptography, in particular ED25519, provided by Libsodium.

Class ED25519::scalar and ED25519::curve_point are naive encapsulations of elements in integer field and points on elliptic curve. The scalar is really a big integer in a prime field with 
$$p=2^{252} + 27742317777372353535851937790883648493.$$

The curve_point, which represents a point on curve ED25519, is really the X coordinate of that point.

The simplest_OT does not provide network/multiprocess communication, so the user needs to get it done themselves:) - This is simple anyway, you need only to understand the protocol (which is also simple), and transmit the messages according to.

## Disclaimer
 This is a small toy project, and I'm new to Libsodium, elliptic curve cryptography, etc. So this project may not provide (if it may provide any!) the security level you may need.

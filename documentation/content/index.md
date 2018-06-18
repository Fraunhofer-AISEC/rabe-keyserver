---
date: 2018-03-08T21:07:13+01:00
title: R-ABE Keyserver
type: index
weight: 10
---

Welcome to the R-ABE Keyserver API! This REST API wraps the attribute based encryption (ABE) schemes of the R-ABE library and can be used to set up an ABE key server.

Note that the API is still under development and must not be used in production. We rather provide it as an easy way to get started with R-ABE, without writing your own standalone program in Rust or C.

Currently, the keyserver API supports only the "BSW" scheme, as described in [1], but we plan to add support for all six schemes implemented by R-ABE.



[1] _John Bethencourt, Amit Sahai, and Brent Waters. Ciphertext-policy attribute-based encryption. in IEEE Symposium on Security and Privacy, pages 321–334, 2007._


# Privileged APIs

Privileged APIs provide administrative access to the keyserver and must not be exposed to the end user. They are used to manage users and setup cryptographic schemes.

## Scheme Setup

An ABE scheme must be initialized before it can be used. During initialization, the key material for the keyserver is created and a session ID is issued that is required in further requests within this scheme.


## Key/Attribute Generation

After setting up the scheme, the keyserver is in possession of master keys for the scheme, but there no user keys yet. To create a user key, the `keygen` endpoint can be used. Keys are typically only assigned to _attributes_, i.e. you will not create the keys for a user but for a set of attributes.

## Creating users


# Encryption

In ciphertext-policy schemes (CP-ABE), data is encrypted for a _policy_ over attributes. How a policy looks like depends on the scheme, but in most cases it will be a boolean expression of attributes for which keys have been created in the previous phase.

To encrypt, you will need to provide the session ID, the plaintext data, and the desired policy.

# Decryption

In contrast to classical public key cryptography, decryption is not restricted to the owner of a single private key, but rather any private key for attributes matching the encryption policy will be able to decrypt data.

To use the `decrypt` endpoint, you will need to provide the session ID, the username, and the ciphertext structure.


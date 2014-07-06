# aes-gcm-wrapper - AES-GCM made less difficult
0.0.9 - 6 July 2014

### What is aes-gcm-wrapper?

`aes-gcm-wrapper.{c,h}` is small wrapper around OpenSSL:s implementation of AES-GCM which can either be used in practice or be used as an example. It will hopefully make your life easier. The author hopes that this wrapper will help making usage of AES-GCM more secure by basing it on a robust implementation.

### What is AES-GCM?

AES-GCM is the AES cipher using the GCM mode of operation. It supports encryption and authentication in the same construction. Simply put, the GCM mode can be thought of as the CTR mode with the addition that it creates an Authentication Tag ("tag") similar to a MAC that can be used to authenticate the message. An extra feature of GCM is that it supports AAD (Additional Authenticated Data) which is arbitrary data that will be authenticated in the tag but not encrypted. Using AAD is optional.

The "input" when encrypting a message with AES-GCM is (key, iv, [aad], [plaintext]) and the "output" is (tag, [ciphertext]).

The "input" when decrypting a message with AES-GCM is (key, iv, [aad], [ciphertext], tag) and the "output" is (verified?, [plaintext]).

When encrypting, it's valid to input:

* Plaintext and AAD.
* Plaintext only (the most common case).
* AAD only.

## Usage

Please see `aes-gcm-wrapper.h` for full documentation. Please see `example.c` for a full example.

### Encryption

    unsigned char IV[16], KEY[16], out[5], tag[AES_GCM_MAX_TAG_SIZE];
    AES_GCM_CTX *ctx = aes_gcm_create();
    if (ctx == NULL)
        // handle error
    if (aes_gcm_init_encrypt(128, KEY, sizeof(IV), IV) > 0)
        // handle error
    if (aes_gcm_encrypt_update(ctx, 5, "hello", out) > 0)
        // handle error
    if (aes_gcm_encrypt_finalize(ctx, AES_GCM_MAX_TAG_SIZE, tag) > 0)
        // handle error

### Decryption

    unsigned char IV[16], KEY[16], out[5], CIPHERTEXT[5], TAG[AES_GCM_MAX_TAG_SIZE];
    int verified;
    AES_GCM_CTX *ctx = aes_gcm_create();
    if (ctx == NULL)
        // handle error
    if (aes_gcm_init_decrypt(128, KEY, sizeof(IV), IV, AES_GCM_MAX_TAG_SIZE, TAG) > 0)
        // handle error
    if (aes_gcm_decrypt_update(ctx, 5, CIPHERTEXT, out) > 0)
        // handle error
    if (aes_gcm_decrypt_finalize(ctx, &verify) > 0)
        // handle error
    if (!verified)
        // authentication failed - message is corrupted or tampered with

## Installing and tests

aes-gcm-wrapper can be built as a shared library but it's more convenient to just copy it around when needed. The only dependency is linking against libcrypto (`gcc ... -lcrypto` for example). The OpenSSL development/header files are required as well.

`test.c` contains test vectors. This can be built by running `make`.

## Questions And Answers

### Multi-threading?

This wrapper is not thread safe at the moment. Calling encryption/decryption functions from different threads without synchronization will likely result in errors or crashes.

### Any good alternatives to using AES-GCM?

An alternative would be, for example, AES-CTR with HMAC-SHA1/SHA256, encrypt-then-mac. The author doesn't recommend using one over the other.

## Author

aes-gcm-wrapper is written by Björn Edström in 2014.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

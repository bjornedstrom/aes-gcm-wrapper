/*
 * Copyright (C) 2014 Björn Edström <be@bjrn.se>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

 /*
 * This product includes software developed by the OpenSSL Project for
 * use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 */

/*
 * aes-gcm-wrapper version 0.0.9 - July 6 2014
 */

#ifndef AES_GCM_WRAPPER_H
#define AES_GCM_WRAPPER_H

/*
 * ERROR HANDLING
 * ==============
 *
 * All the functions in this wrapper will return 0 on success and
 * non-zero on error. The only exception is the very simple
 * aes_gcm_create() which returns NULL on error instead.
 *
 * As a convention, error codes >0 are "hard" usage errors or internal
 * errors that prevent further encryption or decryption. In this case
 * the caller must abort and fix problems with input.
 *
 * Error codes <0 are "soft" failures which means the function
 * completed succesfully but is still considered an error condition:
 * for example on authentication failures. Please see the
 * documentation for aes_gcm_decrypt_finalize() below for further
 * information.
 *
 * The error codes below can be returned:
 */

// Generic error code.
#define AES_GCM_ERR 1

// Indicates a problem with key, iv, tag or ctx.
#define AES_GCM_ERR_INVALID_KEY_SIZE (AES_GCM_ERR + 1)
#define AES_GCM_ERR_INVALID_KEY (AES_GCM_ERR + 2)
#define AES_GCM_ERR_INVALID_IV (AES_GCM_ERR + 3)
#define AES_GCM_ERR_INVALID_TAG (AES_GCM_ERR + 4)
#define AES_GCM_ERR_INVALID_CTX (AES_GCM_ERR + 5)

// Indicates a problem with the underlying crypto library when
// encrypting, decrypting or setting AAD data.
#define AES_GCM_ERR_ENCRYPT (AES_GCM_ERR + 10)
#define AES_GCM_ERR_DECRYPT (AES_GCM_ERR + 11)
#define AES_GCM_ERR_AAD (AES_GCM_ERR + 12)

// Indicates that the aes_gcm_* functions were called in the wrong
// order. This is described in FUNCTION OVERVIEW below.
#define AES_GCM_ERR_ORDERING (AES_GCM_ERR + 20)

// Authentication failed - message is corrupted.
#define AES_GCM_ERR_AUTH (-1)

/*
 * BUFFER/MEMORY HANDLING
 * ======================
 *
 * The convention in this wrapper is to use the size_t type when
 * specifing sizes/counts as number of *bytes*. When this wrapper
 * wants number of bits instead, the parameter is prefixed with _bits
 * and the type is an int instead.
 *
 * We define AES_GCM_MAX_TAG_SIZE as the largest size (in bytes) of a
 * GCM tag. This can be used when creating buffers that will hold the
 * tag.
 *
 * SECURITY NOTE: In general it's advised to always use the largest
 * tag size possible. Before using a shorter tag (which this wrapper
 * supports), please consult NIST 800-38D Appendix C.
 */

#define AES_GCM_MAX_TAG_SIZE 16

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * FUNCTION OVERVIEW
 * =================
 *
 * This wrapper defines these functions:
 *
 *   - aes_gcm_create()
 *   - aes_gcm_init_encrypt()
 *   - aes_gcm_init_decrypt()
 *   - aes_gcm_destroy()
 *   - aes_gcm_set_tag() - OPTIONAL
 *   - aes_gcm_update_aad() - OPTIONAL
 *   - aes_gcm_encrypt_update - OPTIONAL
 *   - aes_gcm_encrypt_finalize()
 *   - aes_gcm_decrypt_update - OPTIONAL
 *   - aes_gcm_decrypt_finalize()
 *
 * These functions MUST be called in the order below, if they are
 * called at all. Failure to call the functions in this order will
 * result in the AES_GCM_ERR_ORDERING return code.
 *
 *   1. aes_gcm_create()
 *   2. aes_gcm_init_encrypt() / aes_gcm_init_decrypt()
 *   3. aes_gcm_update_aad()
 *   4. aes_gcm_encrypt_update() / aes_gcm_decrypt_update()
 *   5. aes_gcm_encrypt_finalize() / aes_gcm_decrypt_finalize()
 *   6. aes_gcm_destroy()
 *
 * Before calling the finalize() function, you must have called one or
 * both:
 *
 *   - aes_gcm_update_aad()
 *   - aes_gcm_encrypt_update() / aes_gcm_decrypt_update()
 *
 * SECURITY NOTE: Extra special care must be taken to call
 * aes_gcm_decrypt_finalize() correctly. See the discussion further
 * below.
 */

/*
 * FUNCTIONS
 * =========
 */

/*
 * Below are the functions for creating/destroying
 * encryption/decryption contexts. For both functions, "key_size_bits"
 * is one of 128, 192 or 256 for AES-128, AES-192 and AES-256
 * respectively. The functions assume that the size of the "key"
 * buffer is key_size_bits/8.
 *
 * It is recommended that the "iv_size" is 96 bits, per
 * Iwata-Ohashi-Minematsu.
 *
 * When creating a decryption context, the GCM tag can optionally be
 * given at creation. If "tag" is NULL, it is up to the user of the
 * wrapper to call aes_gcm_set_tag() described below before doing any
 * decryption.
 */
typedef struct aes_gcm_ctx AES_GCM_CTX;

AES_GCM_CTX* aes_gcm_create(void);

int aes_gcm_destroy(AES_GCM_CTX *ctx);

int aes_gcm_init_encrypt(
	AES_GCM_CTX *ctx,
	int key_size_bits, const unsigned char *key,
	size_t iv_size, const unsigned char *iv);

int aes_gcm_init_decrypt(
	AES_GCM_CTX *ctx,
	int key_size_bits, const unsigned char *key,
	size_t iv_size, const unsigned char *iv,
	size_t tag_size, const unsigned char *tag);

/*
 * If no tag was given in aes_gcm_create_decrypt then it can be set
 * here. We provide this function because modern versions of OpenSSL
 * (1.0.1d) allow postponing setting the tag until right before
 * aes_gcm_decrypt_finalize(), which may be desirable in some cases.
 *
 * For portability it is recommended to set the tag immediately in
 * aes_gcm_create_decrypt().
 */
int aes_gcm_set_tag(
	AES_GCM_CTX *ctx,
	size_t tag_size, const unsigned char *tag);

/*
 * This function can be called zero, one or more times to add
 * Additional Authenticated Data (AAD) which will be authenticated but
 * not encrypted.
 *
 * This function is used both for encryption and decryption. If AAD is
 * present this function should be called before any other
 * encryption/decryption functions.
 */
int aes_gcm_update_aad(
	AES_GCM_CTX *ctx,
	size_t aad_size, const unsigned char *aad);

/*
 * The encryption/decryption functions. aes_gcm_{encrypt,
 * decrypt}_update() are called to encrypt/decrypt parts of the
 * plaintext/ciphertext. If no plaintext/ciphertext exist then do not
 * call these functions.
 *
 * Once encryption is done, call aes_gcm_encrypt_finalize() to get the
 * tag.
 *
 * Once decryption is done, call aes_gcm_decrypt_finalize() to verify
 * the tag given at context creation.
 *
 * SECURITY NOTE: If aes_gcm_decrypt_finalize() sets "verified" to 0,
 * then there's a mismatch and the ciphertext is corrupted. The
 * ciphertext and decrypted plaintext should be discarded without
 * further processing. If verification fails, this function will also
 * return AES_GCM_ERR_AUTH.
 */
int aes_gcm_encrypt_update(
	AES_GCM_CTX *ctx,
	size_t plaintext_size, const unsigned char *plaintext,
	unsigned char *out_buf);

int aes_gcm_encrypt_finalize(
	AES_GCM_CTX *ctx,
	size_t tag_size, unsigned char *tag_out);

int aes_gcm_decrypt_update(
	AES_GCM_CTX *ctx,
	size_t ciphertext_size, const unsigned char *ciphertext,
	unsigned char *out_buf);

/*
 * See SECURITY NOTE above. It is suggested this function is called as
 *
 *   int verified;
 *   if (aes_gcm_decrypt_finalize(ctx, &verified) > 0) {
 *     // handle hard errors
 *   }
 *   if (!verified) {
 *     // tag mismatch - discard message.
 *   }
 *
 * Optionally, it can be called as:
 *
 *   int verified;
 *   int ret = aes_gcm_decrypt_finalize(ctx, &verified);
 *   if (ret < 0)
 *     // handle hard errors
 *   if (ret == AES_GCM_ERR_AUTH)
 *     // tag mismatch - discard message.
 */
int aes_gcm_decrypt_finalize(
	AES_GCM_CTX *ctx,
	int *verified);

/*
 * End of documentation.
 */

#ifdef  __cplusplus
}
#endif
#endif /* AES_GCM_WRAPPER_H */

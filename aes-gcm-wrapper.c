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

#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <aes-gcm-wrapper.h>


#define ENCRYPT 1
#define DECRYPT 2

#define STATE_CREATE 0
#define STATE_AAD 1
#define STATE_CRYPT 2
#define STATE_FINAL 3


struct aes_gcm_ctx {
	EVP_CIPHER_CTX *ctx;

	// If this is a encrypt or decrypt context.
	int type;

	// AES key size in bits (128, 192, 256).
	int key_size_bits;

	/* Keep track of function call order. For example
	 * aes_gcm_update_aad() must be called before any
	 * encryption/decryption functions. */
	int state;

	// TODO (bjorn): I think we can skip this copy.
	int tag_size;
	unsigned char *tag;
};


struct aes_gcm_ctx *aes_gcm_create(void)
{
	struct aes_gcm_ctx *ctx_outer = OPENSSL_malloc(sizeof(struct aes_gcm_ctx));

	if (ctx_outer == NULL)
		return NULL;

	ctx_outer->ctx = NULL;

	return ctx_outer;
}


int aes_gcm_destroy(struct aes_gcm_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->ctx);
	if (ctx->tag)
		OPENSSL_free(ctx->tag);
	OPENSSL_free(ctx);

	return 0;
}


int _aes_gcm_init_internal(
	struct aes_gcm_ctx* ctx,
	int action,
	int key_size_bits, const unsigned char *key,
	size_t iv_size, const unsigned char *iv)
{
	const EVP_CIPHER *cipher;

	assert(ctx);
	assert(action == ENCRYPT || action == DECRYPT);
	//assert(key_size_bits == 128 || key_size_bits == 192 || key_size_bits == 256);
	//assert(key != NULL);
	//assert(iv != NULL);

	if (!(key_size_bits == 128 || key_size_bits == 192 || key_size_bits == 256))
		return AES_GCM_ERR_INVALID_KEY_SIZE;

	if (key == NULL)
		return AES_GCM_ERR_INVALID_KEY;

	if (iv == NULL)
		return AES_GCM_ERR_INVALID_IV;

	switch (key_size_bits) {
	case 128:
		cipher = EVP_aes_128_gcm();
		break;
	case 192:
		cipher = EVP_aes_192_gcm();
		break;
	case 256:
		cipher = EVP_aes_256_gcm();
		break;
	default:
		// This shouldn't happen.
		assert(0);
		return AES_GCM_ERR;
	}

	EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx)
		return AES_GCM_ERR;

	if (EVP_EncryptInit_ex(evp_ctx, cipher, NULL, NULL, NULL) == 0) {
		return AES_GCM_ERR;
	}

	if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL) == 0) {
		return AES_GCM_ERR_INVALID_IV;
	}

	if (action == ENCRYPT) {
		if (EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key, iv) == 0) {
			// TODO (bjorn): This could be invalid KEY/IV?
			return AES_GCM_ERR;
		}
	} else if (action == DECRYPT) {
		if (EVP_DecryptInit_ex(evp_ctx, NULL, NULL, key, iv) == 0) {
			// TODO: see above.
			return AES_GCM_ERR;
		}
	}

	ctx->ctx = evp_ctx;
	ctx->type = action;
	ctx->key_size_bits = key_size_bits;
	ctx->state = STATE_CREATE;
	ctx->tag_size = 0;
	ctx->tag = NULL;

	return 0;
}


int aes_gcm_init_encrypt(
	struct aes_gcm_ctx* ctx,
	int key_size_bits, const unsigned char *key,
	size_t iv_size, const unsigned char *iv)
{
	return _aes_gcm_init_internal(
		ctx,
		ENCRYPT,
		key_size_bits, key,
		iv_size, iv);
}


int aes_gcm_set_tag(
	struct aes_gcm_ctx *ctx,
	size_t tag_size, const unsigned char *tag)
{
	//assert(tag != NULL);
	//assert(tag_size >= 1 && tag_size <= AES_GCM_MAX_TAG_SIZE);

	if ((tag == NULL) || !(tag_size >= 1 && tag_size <= AES_GCM_MAX_TAG_SIZE))
		return AES_GCM_ERR_INVALID_TAG;

	if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, tag_size, (unsigned char *)tag) == 0) {
		return AES_GCM_ERR_INVALID_TAG;
	}

	ctx->tag_size = tag_size;
	ctx->tag = OPENSSL_malloc(tag_size + 1);
	memcpy(ctx->tag, tag, tag_size);

	return 0;
}


int aes_gcm_init_decrypt(
	struct aes_gcm_ctx* ctx,
	int key_size_bits, const unsigned char *key,
	size_t iv_size, const unsigned char *iv,
	size_t tag_size, const unsigned char *tag)
{
	//assert((tag == NULL) || (tag && (tag_size >= 1 && tag_size <= AES_GCM_MAX_TAG_SIZE)));

	if ((tag == NULL) || !(tag_size >= 1 && tag_size <= AES_GCM_MAX_TAG_SIZE))
		return AES_GCM_ERR_INVALID_TAG;

	int ret = _aes_gcm_init_internal(
		ctx,
		DECRYPT,
		key_size_bits, key,
		iv_size, iv);

	if (ret != 0)
		return ret;

	/* Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier
         * required the tag before any AAD or ciphertext */
	if (tag) {
		ret = aes_gcm_set_tag(ctx, tag_size, tag);

		if (ret != 0)
			return ret;
	}

	return 0;
}


int aes_gcm_encrypt_update(
	struct aes_gcm_ctx *ctx,
	size_t plaintext_size, const unsigned char *plaintext,
	unsigned char *out_buf)
{
	//assert(ctx->state <= STATE_CRYPT);
	assert(plaintext != NULL); // keep this

	if (ctx->type != ENCRYPT)
		return AES_GCM_ERR_INVALID_CTX;

	if (ctx->state > STATE_CRYPT)
		return AES_GCM_ERR_ORDERING;

	int outl = 0;
	if (EVP_EncryptUpdate(ctx->ctx, out_buf, &outl, plaintext, plaintext_size) == 0) {
		return AES_GCM_ERR_ENCRYPT;
	}

	// TODO (bjorn): Can this ever happen?
	assert(outl == plaintext_size);

	ctx->state = STATE_CRYPT;

	return 0;
}


int aes_gcm_decrypt_update(
	struct aes_gcm_ctx *ctx, size_t ciphertext_size, const unsigned char *ciphertext,
	unsigned char *out_buf)
{
	//assert(ctx->state <= STATE_CRYPT);
	assert(ciphertext != NULL);

	if (ctx->type != DECRYPT)
		return AES_GCM_ERR_INVALID_CTX;

	if (ctx->state > STATE_CRYPT)
		return AES_GCM_ERR_ORDERING;

	int outl = 0;
	if (EVP_DecryptUpdate(ctx->ctx, out_buf, &outl, ciphertext, ciphertext_size) == 0) {
		return AES_GCM_ERR_DECRYPT;
	}

	// TODO (bjorn): Can this ever happen?
	assert(outl == ciphertext_size);

	ctx->state = STATE_CRYPT;

	return 0;
}


int aes_gcm_update_aad(
	struct aes_gcm_ctx *ctx,
	size_t aad_size, const unsigned char *aad)
{
	// A restriction in OpenSSL 1.0.1c and earlier required the tag before any AAD or ciphertext
	// TODO (bjorn): Check versions.

	assert(aad != NULL);

	// This must be called after creation
	if (ctx->state > STATE_AAD)
		return AES_GCM_ERR_ORDERING;

	int outl = 0;
	if (ctx->type == ENCRYPT) {
		if (EVP_EncryptUpdate(ctx->ctx, NULL, &outl, aad, aad_size) == 0) {
			return AES_GCM_ERR_AAD;
		}
	} else if (ctx->type == DECRYPT) {
		if (EVP_DecryptUpdate(ctx->ctx, NULL, &outl, aad, aad_size) == 0) {
			return AES_GCM_ERR_AAD;
		}
	}

	// TODO (bjorn): Can this ever happen?
	assert(outl == aad_size);

	ctx->state = STATE_AAD;

	return 0;
}


int aes_gcm_encrypt_finalize(
	struct aes_gcm_ctx *ctx,
	size_t tag_size, unsigned char *tag_out)
{
	assert(tag_out);

	if (ctx->state < STATE_AAD)
		return AES_GCM_ERR_ORDERING;

	if (!(tag_size >= 1 && tag_size <= AES_GCM_MAX_TAG_SIZE))
		return AES_GCM_ERR_INVALID_TAG;

	ctx->state = STATE_FINAL;

	unsigned char dummy[16];
	int outlen = 0;
	if (EVP_EncryptFinal_ex(ctx->ctx, dummy, &outlen) == 0) {
		return AES_GCM_ERR_ENCRYPT;
	}

	// TODO (bjorn): Can this ever happen?
	assert(outlen == 0);

	if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG, tag_size, tag_out) == 0) {
		return AES_GCM_ERR_INVALID_TAG;
	}

	return 0;
}


int aes_gcm_decrypt_finalize(
	struct aes_gcm_ctx *ctx,
	int *verified)
{
	assert(verified != NULL);

	if (ctx->state < STATE_AAD)
		return AES_GCM_ERR_ORDERING;

	ctx->state = STATE_FINAL;

#if 0
	assert(ctx->tag != NULL);

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, ctx->tag_size, ctx->tag) == 0) {
		return AES_GCM_INVALID_TAG; // ???
	}
#endif

	unsigned char dummy[16];
	int outlen = 0;
	int rv = EVP_DecryptFinal_ex(ctx->ctx, dummy, &outlen);

	// This will always be 0 for GCM.
	assert(outlen == 0);

	// EVP_DecryptFinal_ex said authentication failed.
	if (rv == 0) {
		*verified = 0;

		// We return -1 here to distinguish from openssl error codes.
		return AES_GCM_ERR_AUTH;
	} else {
		*verified = 1;
	}

	return 0;
}

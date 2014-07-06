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

#include <stdio.h>
#include <stdlib.h>

#include <aes-gcm-wrapper.h>


void printhex(unsigned char *buf, size_t size)
{
	size_t i;

	printf("{");
	for (i = 0; i < size; i++) {
		printf("0x%02x", buf[i]);
		if (i < size - 1) {
			printf(", ");
		}
	}
	printf("}\n");
}


void encrypt()
{
	int ret;
	AES_GCM_CTX *ctx;

	ctx = aes_gcm_create();
	if (!ctx) {
		fprintf(stderr, "_create failed\n");
		exit(1);
	}

	ret = aes_gcm_init_encrypt(
		ctx,
		128, "abcd0123fooobaar",
		16, "iviviviviviviviv");
	if (ret > 0) {
		fprintf(stderr, "_init_encrypt failed with %d\n", ret);
		return;
	}

	ret = aes_gcm_update_aad(ctx, 3, "foo");
	if (ret > 0) {
		fprintf(stderr, "_update_aad failed with %d\n", ret);
		return;
	}

	unsigned char out[5] = {0};
	ret = aes_gcm_encrypt_update(ctx, 5, "hello", out);
	if (ret > 0) {
		fprintf(stderr, "_encrypt_update failed with %d\n", ret);
		return;
	}

	printhex(out, 5);

	unsigned char tag[AES_GCM_MAX_TAG_SIZE] = {0};

	ret = aes_gcm_encrypt_finalize(ctx, 4, tag);
	if (ret > 0) {
		fprintf(stderr, "_encrypt_finalize failed with %d\n", ret);
		return;
	}

	printhex(tag, 16);

	aes_gcm_destroy(ctx);
}


void decrypt()
{
	unsigned char small_tag[4] = {0x32, 0xd7, 0xc1, 0xcd};
	AES_GCM_CTX *ctx;
	int ret;

	ctx = aes_gcm_create();
	if (!ctx) {
		fprintf(stderr, "_create failed\n");
		exit(1);
	}

	ret = aes_gcm_init_decrypt(
		ctx,
		128, "abcd0123fooobaar",
		16, "iviviviviviviviv",
		4, small_tag);
	if (ret > 0) {
		fprintf(stderr, "_init_decrypt failed with %d\n", ret);
		return;
	}

	unsigned char ciphertext[5] = {0xe8, 0x33, 0x4b, 0x54, 0xbf};
	unsigned char out[6] = {0};

	ret = aes_gcm_decrypt_update(ctx, 5, ciphertext, out);
	if (ret > 0) {
		fprintf(stderr, "_decrypt_update failed with %d\n", ret);
		return;
	}

	int verify;
	ret = aes_gcm_decrypt_finalize(ctx, &verify);
	if (ret > 0) {
		fprintf(stderr, "_decrypt_finalize failed with %d\n", ret);
		return;
	}

	// IMPORTANT
	if (!verify) {
		printf("VERIFICATION FAILED\n");
	} else {
		printf("%s\n", out);
	}

	aes_gcm_destroy(ctx);
}


int main()
{
	encrypt();
	decrypt();

	return 0;
}

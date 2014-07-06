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
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


int undigit(char digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';
	else if (digit >= 'a' && digit <= 'f')
		return 10 + digit - 'a';
	else if (digit >= 'A' && digit <= 'A')
		return 10 + digit - 'A';
	return -1;
}


unsigned char *parse_hex_string(char *hex, size_t hex_len)
{
	unsigned char *buf = OPENSSL_malloc(hex_len + 1);
	size_t i;
	for (i = 0; i < hex_len; i += 2) {
		buf[i >> 1] = (undigit(hex[i]) << 4) | (undigit(hex[i + 1]) & 0xf);
	}
	return buf;
}


void run_test_case(int vec_num, char *key, char *iv, char *hdr, char *ptx, char *ctx, char *tag)
{
	size_t key_size, iv_size, hdr_size, ptx_size, ctx_size, tag_size;
	unsigned char *KEY, *IV, *HDR, *PTX, *CTX, *TAG;
	AES_GCM_CTX *handle;

	if (key) {
		key_size = strlen(key) / 2;
		KEY = parse_hex_string(key, key_size * 2);
#ifdef PRINT_VECTORS
		printf("KEY(%zd) = ", key_size);
		printhex(KEY, key_size);
#endif
	}

	if (iv) {
		iv_size = strlen(iv) / 2;
		IV = parse_hex_string(iv, iv_size * 2);
#ifdef PRINT_VECTORS
		printf("IV(%zd) = ", iv_size);
		printhex(IV, iv_size);
#endif
	}

	if (hdr) {
		hdr_size = strlen(hdr) / 2;
		HDR = parse_hex_string(hdr, hdr_size * 2);
#ifdef PRINT_VECTORS
		printf("HDR(%zd) = ", hdr_size);
		printhex(HDR, hdr_size);
#endif
	}

	if (ptx) {
		ptx_size = strlen(ptx) / 2;
		PTX = parse_hex_string(ptx, ptx_size * 2);
#ifdef PRINT_VECTORS
		printf("PTX(%zd) = ", ptx_size);
		printhex(PTX, ptx_size);
#endif
	}

	if (ctx) {
		ctx_size = strlen(ctx) / 2;
		CTX = parse_hex_string(ctx, ctx_size * 2);
#ifdef PRINT_VECTORS
		printf("CTX(%zd) = ", ctx_size);
		printhex(CTX, ctx_size);
#endif
	}

	if (tag) {
		tag_size = strlen(tag) / 2;
		TAG = parse_hex_string(tag, tag_size * 2);
#ifdef PRINT_VECTORS
		printf("TAG(%zd) = ", tag_size);
		printhex(TAG, tag_size);
#endif
	}

	printf("running test vector %d\n", vec_num);
	int failure = 0;


	/* encrypt */
	handle = aes_gcm_create();

	aes_gcm_init_encrypt(handle, key_size * 8, KEY, iv_size, IV);

	if (hdr) {
		aes_gcm_update_aad(handle, hdr_size, HDR);
	}

	if (ptx) {
		unsigned char *out = OPENSSL_malloc(ptx_size + 1);

		aes_gcm_encrypt_update(handle, ptx_size, PTX, out);

		if (memcmp(CTX, out, ptx_size)) {
			failure = 1;
			fprintf(stderr, "TEST CASE %d FAILURE: encrypt != CTX\n", vec_num);
		}

		OPENSSL_free(out);
	}

	if (tag) {
		unsigned char tag_out[16] = {0};
		aes_gcm_encrypt_finalize(handle, 16, tag_out);

		if (memcmp(TAG, tag_out, 16)) {
			failure = 1;
			fprintf(stderr, "TEST CASE %d FAILURE: encrypt tag != TAG\n", vec_num);
			printhex(tag_out, 16);
		}
	}

	aes_gcm_destroy(handle);

	/* decrypt */
	handle = aes_gcm_create();

	aes_gcm_init_decrypt(handle, key_size * 8, KEY, iv_size, IV, tag_size, TAG);

	if (hdr) {
		aes_gcm_update_aad(handle, hdr_size, HDR);
	}

	if (ctx) {
		unsigned char *out = OPENSSL_malloc(ctx_size + 1);

		aes_gcm_decrypt_update(handle, ctx_size, CTX, out);

		if (memcmp(PTX, out, ctx_size)) {
			failure = 1;
			fprintf(stderr, "TEST CASE %d FAILURE: decrypt != PTX\n", vec_num);
		}

		OPENSSL_free(out);
	}

	if (tag) {
		int verified;
		int ret = aes_gcm_decrypt_finalize(handle, &verified);

		if (!verified) {
			failure = 1;
			fprintf(stderr, "TEST CASE %d FAILURE: decrypt tag mismatch\n", vec_num);
		}
	}

	aes_gcm_destroy(handle);

	if (failure)
		printf("test vector %d FAILED\n", vec_num);
	else
		printf("test vector %d SUCCEEDED\n", vec_num);

	/* done */

	if (key) OPENSSL_free(KEY);
	if (iv) OPENSSL_free(IV);
	if (hdr) OPENSSL_free(HDR);
	if (ptx) OPENSSL_free(PTX);
	if (ctx) OPENSSL_free(CTX);
	if (tag) OPENSSL_free(TAG);
}


/*
 * These test vectors are from IEEE P1619
 */
void test_cases()
{
	// VEC 1
	run_test_case(
		1,
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		NULL,
		"00000000000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"d0d1c8a799996bf0265b98b5d48ab919");

	// VEC 2
	run_test_case(
		2,
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"00000000000000000000000000000000",
		NULL,
		NULL,
		"2d45552d8575922b3ca3cc538442fa26");

	// VEC 3
	run_test_case(
		3,
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"ae9b1771dba9cf62b39be017940330b4");

	// VEC 4
	run_test_case(
		4,
		"fb7615b23d80891dd470980bc79584c8b2fb64ce60978f4d17fce45a49e830b7",
		"dbd1a3636024b7b402da7d6f",
		NULL,
		"a845348ec8c5b5f126f50e76fefd1b1e",
		"5df5d1fabcbbdd051538252444178704",
		"4c43cce5a574d8a88b43d4353bd60f9f");

	// VEC 5
	run_test_case(
		5,
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"101112131415161718191a1b",
		"000102030405060708090a0b0c0d0e0f10111213",
		"202122232425262728292a2b2c2d2e2f3031323334353637",
		"591b1ff272b43204868ffc7bc7d521993526b6fa32247c3c",
		"7de12a5670e570d8cae624a16df09c08");

	// VEC 6
	char *long_hdr = malloc(2*256*256 + 1);
	long_hdr[0] = 0;
	int i;

	for (i = 0; i < 256; i++) {
		strcat(long_hdr,
		       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
		       "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" \
		       "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" \
		       "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" \
		       "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" \
		       "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" \
		       "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" \
		       "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	}

	run_test_case(
		6,
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"101112131415161718191a1b",
		long_hdr,
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"591b1ff272b43204868ffc7bc7d521993526b6fa32247c3c4057f3eae7548cef",
		"a1de5536e97edddccd26eeb1b5ff7b32");

	free(long_hdr);

	// VEC 7
	run_test_case(
		7,
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"101112131415161718191a1b",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" \
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" \
		"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" \
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" \
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" \
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" \
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"793b3fd252941224a6afdc5be7f501b9150696da12045c1c6077d3cac774accf" \
		"c3d530d848d665d81a49cbb500b88bbb624ae61d1667229c302dc6ff0bb4d70b" \
		"dbbc8566d6f5b158da99a2ff2e01dda629b89c34ad1e5feba70e7aae4328289c" \
		"3629b0588350581ca8b97ccf1258fa3bbe2c5026047ba72648969cff8ba10ae3" \
		"0e05935df0c693741892b76faf67133abd2cf2031121bd8bb38127a4d2eedeea" \
		"13276494f402cd7c107fb3ec3b24784834338e55436287092ac4a26f5ea7ea4a" \
		"d68d73151639b05b24e68b9816d1398376d8e4138594758db9ad3b409259b26d" \
		"cfc06e722be987b3767f70a7b856b774b1ba2685b368091429fccb8dcdde09e4",
		"87ec837abf532855b2cea169d6943fcd");

	// VEC 8
	run_test_case(
		8,
		"fb7615b23d80891dd470980bc79584c8b2fb64ce6097878d17fce45a49e830b7",
		"dbd1a3636024b7b402da7d6f",
		"36",
		"a9",
		"0a",
		"be987d009a4b349aa80cb9c4ebc1e9f4");

	// VEC 9
	run_test_case(
		9,
		"f8d476cfd646ea6c2384cb1c27d6195dfef1a9f37b9c8d21a79c21f8cb90d289",
		"dbd1a3636024b7b402da7d6f",
		"7bd859a247961a21823b380e9fe8b65082ba61d3",
		"90ae61cf7baebd4cade494c54a29ae70269aec71",
		"ce2027b47a843252013465834d75fd0f0729752e",
		"acd8833837ab0ede84f4748da8899c15");

	// VEC 10
	run_test_case(
		10,
		"dbbc8566d6f5b158da99a2ff2e01dda629b89c34ad1e5feba70e7aae4328289c",
		"cfc06e722be987b3767f70a7b856b774",
		NULL,
		"ce2027b47a843252013465834d75fd0f",
		"dc03e524830d30f88e197f3acace66ef",
		"9984eff6905755d1836f2db04089634c");


	// VEC 11
	run_test_case(
		11,
		"0e05935df0c693741892b76faf67133abd2cf2031121bd8bb38127a4d2eedeea",
		"74b1ba2685b368091429fccb8dcdde09e4",
		"7bd859a247961a21823b380e9fe8b65082ba61d3",
		"90ae61cf7baebd4cade494c54a29ae70269aec71",
		"6be65e56066c4056738c03fe2320974ba3f65e09",
		"6108dc417bf32f7fb7554ae52f088f87");

}


int main()
{
	test_cases();

	return 0;
}

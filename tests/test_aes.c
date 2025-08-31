#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_common.h"
#include "helper.h"
#include "aes.h"

struct test_case {
	int key_bits;
	uint8_t key[32];
	uint8_t input[16];
	uint8_t expected_out[16];
};

static int test_aes(
	const uint8_t *key,
	int key_bits,
	const uint8_t *input,
	const uint8_t *expected_out)
{
	uint8_t output[16];
	aes_key enc_key, dec_key;

	aes_set_encrypt_key(key, key_bits, &enc_key);
	aes_set_decrypt_key(key, key_bits, &dec_key);

	aes_encrypt(input, output, &enc_key);

	if (memcmp(expected_out, output, sizeof(output))) {
		fprintf(stderr, "encrypt failed\n");
		return 0;
	}

	aes_decrypt(expected_out, output, &dec_key);

	if (memcmp(input, output, sizeof(output))) {
		fprintf(stderr, "decrypt failed\n");
		return 0;
	}

	return 1;
}

static void do_test(struct test_case *test, int test_no)
{
	UNUSED(test_no);
	if (!test_aes(test->key, test->key_bits, test->input, test->expected_out))
		fail_test();
}

int main(int argc, char **argv)
{
	struct test_case tests[] = {
	{
		.key_bits = 256,
		.key = {
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13,
			0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b,
			0x1c, 0x1d, 0x1e, 0x1f,
		},
		.input = {
			0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff,
		},
		.expected_out = {
			0x8e, 0xa2, 0xb7, 0xca,
			0x51, 0x67, 0x45, 0xbf,
			0xea, 0xfc, 0x49, 0x90,
			0x4b, 0x49, 0x60, 0x89,
		}
	}};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_common.h"
#include "encrypt/chacha20.h"
#include "encrypt/poly1305.h"
#include "helper.h"

struct test_case {
	const char *plain_text;
	const char *ad;
	const char *key;
	const char *nonce;
	const char *cipher_text;
	const char *mac;
};

unsigned char *stobin(const char *hex_s, size_t *bin_len)
{
	size_t hex_len = strlen(hex_s);
	unsigned char *bin_s = malloc(hex_len / 2);
	binarize(hex_s, hex_len, bin_s);
	*bin_len = hex_len / 2;
	return bin_s;
}

static int test_aead_write(
	const char *plain_text_hex,
	const char *ad_hex,
	const char *key_hex,
	const char *nonce_hex,
	const char *cipher_text_hex,
	const char *mac_hex)
{
	size_t plain_text_len, ad_len, key_len, nonce_len, cipher_text_len, mac_len;
	uint8_t *plain_text = stobin(plain_text_hex, &plain_text_len);
	uint8_t *ad = stobin(ad_hex, &ad_len);
	uint8_t *key = stobin(key_hex, &key_len);
	uint8_t *nonce = stobin(nonce_hex, &nonce_len);
	uint8_t *cipher_text = stobin(cipher_text_hex, &cipher_text_len);
	uint8_t *mac = stobin(mac_hex, &mac_len);
	uint8_t *cipher_text_res = malloc(plain_text_len);
	uint8_t *mac_res = malloc(mac_len);
	crypto_aead_ctx ctx;
	int cipher_ok, mac_ok;

	crypto_aead_init_x(&ctx, key, nonce);
	crypto_aead_write(&ctx, cipher_text_res, mac_res, ad, ad_len, plain_text, plain_text_len);

	cipher_ok = !memcmp(cipher_text_res, cipher_text, cipher_text_len);
	mac_ok = !memcmp(mac_res, mac, mac_len);

	free(plain_text);
	free(ad);
	free(key);
	free(nonce);
	free(cipher_text);
	free(mac);
	free(cipher_text_res);
	free(mac_res);
	return cipher_ok && mac_ok;
}

static void do_test(struct test_case *test, int test_no)
{
	int res = test_aead_write(test->plain_text, test->ad, test->key,
		test->nonce, test->cipher_text, test->mac);
	if (!res)
		fail_test();
	UNUSED(test_no);
}

int main(int argc, char **argv)
{
	struct test_case tests[] = {
	{
		.plain_text =
			"4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
			"637265656e20776f756c642062652069742e",
		.ad    = "50515253c0c1c2c3c4c5c6c7",
		.key   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
		.nonce = "404142434445464748494a4b4c4d4e4f5051525354555657",
		.cipher_text =
			"bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
			"731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
			"2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
			"21f9664c97637da9768812f615c68b13b52e",
		.mac = "c0875924c1c7987947deafd8780acf49",
	}};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}

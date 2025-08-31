#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_common.h"
#include "helper.h"
#include "sha1.h"

struct hmac_sha1_test_case {
	const char *input;
	const char *key;
	const char *expected_mac;
};

static int test_hmac_sha1(const char *input, const char *key, const char *expected_mac)
{
	unsigned char hmac[SHA1_DIGEST_LENGTH];
	char hmac_hex[SHA1_DIGEST_HEX_LENGTH];
	hmac_sha1((uint8_t *)input, strlen(input), (uint8_t *)key, strlen(key), hmac);
	hexlify(hmac, sizeof(hmac), 0, hmac_hex);
	return !strcmp(hmac_hex, expected_mac);
}

static void do_test(struct hmac_sha1_test_case *test, int test_no)
{
	int res = test_hmac_sha1(test->input, test->key, test->expected_mac);
	if (!res)
		fail_test();
	fprintf(stderr, "[%d] %s hmac_sha1(%s, %s) %s %s\n", test_no, STATUS_PREFIX(res),
		test->input, test->key, EQUAL_IF_OK(res), test->expected_mac);
}

int main(int argc, char **argv)
{
	struct hmac_sha1_test_case tests[] = {
		{"Test SHA1-HMAC", "p0hSgbzHGeNJYdCWz3a0tVXHspcsszaF", "9e131c4c4629282ca56d3d5f43b783303d2d0ef6"},
		{"Test with very long key...", "NTXj3wGdFD22SNTjhxA1bD9fmgIfxufcrxvo9JC5xhNIbGQseCQKooYIMVD5ivEIAUv2qAUWbBwUfTVWPRY34cK0oDw1YZycz1Tn3iMiWvruN4IVaLaciBuAwBsucsao", "3b42d72904142ef369a3e9dfee0712e96f67c371"},
		{"At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat", "sssssssssssss", "fe01ba7d8ad605c1637795a1b85d210eafac4faa"},
	};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}

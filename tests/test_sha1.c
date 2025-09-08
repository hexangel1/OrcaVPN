#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_common.h"
#include "helper.h"
#include "sha1.h"

struct sha1_test_case {
	const char *input;
	const char *expected_digest;
};

static int test_sha1(const char *input, const char *expected_digest)
{
	struct sha1_ctxt ctxt;
	u8 digest[SHA1_DIGEST_LENGTH];
	char hex_digest[SHA1_DIGEST_HEX_LENGTH];

	sha1_init(&ctxt);
	sha1_loop(&ctxt, (const u8 *)input, strlen(input));
	sha1_result(&ctxt, digest);
	hexlify(digest, SHA1_DIGEST_LENGTH, 0, hex_digest);
	return !strcmp(hex_digest, expected_digest);
}

static void do_test(struct sha1_test_case *test, int test_no)
{
	int res = test_sha1(test->input, test->expected_digest);
	if (!res)
		fail_test();
	fprintf(stderr, "[%d] %s sha1(%s) %s %s\n", test_no, STATUS_PREFIX(res),
		test->input, EQUAL_IF_OK(res), test->expected_digest);
}

int main(int argc, char **argv)
{
	struct sha1_test_case tests[] = {
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"sha", "d8f4590320e1343a915b6394170650a8f35d6926"},
		{"Sha", "ba79baeb9f10896a46ae74715271b7f586e74640"},
		{"People are strange when you're a stranger", "6d368f5af473cabf3e85fd7c52a17e85e86b5c71"},
		{"The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "03f09f5b158a7a8cdad920bddc29b81c18a551f5"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
		{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259"},
		{"At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat", "3a1f73f90281f96e5b77c764c013e3f9e702b175"},
	};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}

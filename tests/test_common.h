#ifndef TEST_COMMON_H_SENTRY
#define TEST_COMMON_H_SENTRY

#include <stdio.h>

#define TEST_STATUS (!test_passed)

#define STATUS_PREFIX(ok) ((ok) ? "[PASSED]" : "[FAILED]")
#define EQUAL_IF_OK(ok) ((ok) ? "==" : "!=")

#define RUN_TESTS(tests) do { \
	unsigned int i; \
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) \
		do_test(&tests[i]); \
	fprintf(stderr, "%s %s\n", STATUS_PREFIX(test_passed), argv[0]); \
} while (0)

static int test_passed = 1;

static void fail_test(void)
{
	fprintf(stderr, "!!! TEST FAILED !!!\n");
	test_passed = 0;
}

#endif /* TEST_COMMON_H_SENTRY */

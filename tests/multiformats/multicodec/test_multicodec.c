#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multicodec/multicodec_table.h"

static int g_failures = 0;

static void report_result(const char *test_name, int passed, const char *details)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
        return;
    }

    ++g_failures;
    printf("TEST: %-50s | FAIL: %s\n", test_name, details);
}

static void test_negative_lookups(void)
{
    report_result("code_from_name(NULL)", multicodec_code_from_name(NULL) == UINT64_MAX, "expected UINT64_MAX");
    report_result("code_from_name(empty)", multicodec_code_from_name("") == UINT64_MAX, "expected UINT64_MAX");
    report_result("code_from_name(missing)", multicodec_code_from_name("not-a-valid-multicodec") == UINT64_MAX, "expected UINT64_MAX");
    report_result("name_from_code(unknown)", multicodec_name_from_code(UINT64_MAX) == NULL, "expected NULL");
}

static void test_known_samples(void)
{
    const char *name;

    report_result("identity code", multicodec_code_from_name("identity") == MULTICODEC_IDENTITY, "identity code mismatch");
    report_result("ip4 code", multicodec_code_from_name("ip4") == MULTICODEC_IP4, "ip4 code mismatch");
    report_result("tcp code", multicodec_code_from_name("tcp") == MULTICODEC_TCP, "tcp code mismatch");

    name = multicodec_name_from_code(MULTICODEC_IDENTITY);
    report_result("identity name", (name != NULL) && (strcmp(name, "identity") == 0), "identity name mismatch");

    name = multicodec_name_from_code(MULTICODEC_IP4);
    report_result("ip4 name", (name != NULL) && (strcmp(name, "ip4") == 0), "ip4 name mismatch");
}

static void test_table_consistency(void)
{
    size_t i;
    size_t j;
    size_t lookup_failures;
    size_t duplicate_name_failures;

    report_result("table non-empty", multicodec_table_len > 0, "table must not be empty");

    lookup_failures = 0;
    for (i = 0; i < multicodec_table_len; ++i)
    {
        const multicodec_map_t *entry;
        const char *canonical_name;
        uint64_t lookup_code;

        entry = &multicodec_table[i];
        if ((entry->name == NULL) || (entry->name[0] == '\0'))
        {
            ++lookup_failures;
            if (lookup_failures <= 10)
            {
                printf("  table entry %zu has empty/null name\n", i);
            }
            continue;
        }

        lookup_code = multicodec_code_from_name(entry->name);
        if (lookup_code != entry->code)
        {
            ++lookup_failures;
            if (lookup_failures <= 10)
            {
                printf("  code mismatch for name '%s': got 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", entry->name, lookup_code, entry->code);
            }
        }

        canonical_name = multicodec_name_from_code(entry->code);
        if (canonical_name == NULL)
        {
            ++lookup_failures;
            if (lookup_failures <= 10)
            {
                printf("  missing name for code 0x%" PRIx64 "\n", entry->code);
            }
            continue;
        }

        if (multicodec_code_from_name(canonical_name) != entry->code)
        {
            ++lookup_failures;
            if (lookup_failures <= 10)
            {
                printf("  canonical lookup mismatch for code 0x%" PRIx64 " via '%s'\n", entry->code, canonical_name);
            }
        }
    }

    report_result("table lookup consistency", lookup_failures == 0, "one or more table lookup inconsistencies found");

    duplicate_name_failures = 0;
    for (i = 0; i < multicodec_table_len; ++i)
    {
        const char *left_name;

        left_name = multicodec_table[i].name;
        if (left_name == NULL)
        {
            continue;
        }

        for (j = i + 1; j < multicodec_table_len; ++j)
        {
            const char *right_name;

            right_name = multicodec_table[j].name;
            if (right_name == NULL)
            {
                continue;
            }

            if (strcmp(left_name, right_name) == 0)
            {
                ++duplicate_name_failures;
                if (duplicate_name_failures <= 10)
                {
                    printf("  duplicate name '%s' at indexes %zu and %zu\n", left_name, i, j);
                }
            }
        }
    }

    report_result("table unique names", duplicate_name_failures == 0, "duplicate names found in multicodec table");
}

int main(void)
{
    test_negative_lookups();
    test_known_samples();
    test_table_consistency();

    if (g_failures != 0)
    {
        printf("\nSome tests failed. Total failures: %d\n", g_failures);
        return EXIT_FAILURE;
    }

    printf("\nAll multicodec tests passed!\n");
    return EXIT_SUCCESS;
}

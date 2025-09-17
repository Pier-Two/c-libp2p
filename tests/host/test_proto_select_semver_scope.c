#include <stdio.h>
#include <string.h>

#include "src/host/proto_select_internal.h"

static void print_case(const char *name, int ok)
{ printf("TEST: %-50s | %s\n", name, ok ? "PASS" : "FAIL"); }

int main(void)
{
    int ok_all = 1;
    version_triplet_t v = {0};

    /* Matching base_path extracts version */
    int rc1 = extract_version_from_id("/foo/1.2.3", "/foo/", &v);
    int ok1 = (rc1 == 0 && v.major == 1 && v.minor == 2 && v.patch == 3);
    print_case("extract_version_from_id matches base_path", ok1);
    ok_all &= ok1;

    /* Mismatched base_path is rejected */
    memset(&v, 0, sizeof(v));
    int rc2 = extract_version_from_id("/bar/1.2.3", "/foo/", &v);
    int ok2 = (rc2 != 0);
    print_case("extract_version_from_id rejects wrong base_path", ok2);
    ok_all &= ok2;

    /* No base_path falls back to last segment */
    memset(&v, 0, sizeof(v));
    int rc3 = extract_version_from_id("/bar/1.2.3", NULL, &v);
    int ok3 = (rc3 == 0 && v.major == 1 && v.minor == 2 && v.patch == 3);
    print_case("extract_version_from_id without base_path", ok3);
    ok_all &= ok3;

    return ok_all ? 0 : 1;
}


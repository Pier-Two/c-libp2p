#include <stdio.h>
#include <string.h>

#include "src/host/proto_select_internal.h"

static void print_case(const char *name, int ok)
{ printf("TEST: %-60s | %s\n", name, ok ? "PASS" : "FAIL"); }

static int eq_triplet(version_triplet_t a, int maj, int min, int pat)
{ return a.major == maj && a.minor == min && a.patch == pat; }

int main(void)
{
    int ok_all = 1;

    /* version_triplet: valid */
    version_triplet_t v = {0};
    int rc;
    rc = parse_version_triplet("1", &v);
    int ok_v1 = (rc == 0 && eq_triplet(v, 1, 0, 0));
    print_case("parse_version_triplet: '1'", ok_v1); ok_all &= ok_v1;

    rc = parse_version_triplet("2.3", &v);
    int ok_v2 = (rc == 0 && eq_triplet(v, 2, 3, 0));
    print_case("parse_version_triplet: '2.3'", ok_v2); ok_all &= ok_v2;

    rc = parse_version_triplet("3.4.5", &v);
    int ok_v3 = (rc == 0 && eq_triplet(v, 3, 4, 5));
    print_case("parse_version_triplet: '3.4.5'", ok_v3); ok_all &= ok_v3;

    /* version_triplet: malformed */
    rc = parse_version_triplet("1.", &v);
    int ok_vm1 = (rc != 0);
    print_case("parse_version_triplet: '1.' -> error", ok_vm1); ok_all &= ok_vm1;

    rc = parse_version_triplet("1..2", &v);
    int ok_vm2 = (rc != 0);
    print_case("parse_version_triplet: '1..2' -> error", ok_vm2); ok_all &= ok_vm2;

    rc = parse_version_triplet("1.2.3.4", &v);
    int ok_vm3 = (rc != 0);
    print_case("parse_version_triplet: '1.2.3.4' -> error", ok_vm3); ok_all &= ok_vm3;

    rc = parse_version_triplet("1.2.3beta", &v);
    int ok_vm4 = (rc != 0);
    print_case("parse_version_triplet: '1.2.3beta' -> error", ok_vm4); ok_all &= ok_vm4;

    rc = parse_version_triplet("2147483648.0.0", &v); /* > INT_MAX */
    int ok_vm5 = (rc != 0);
    print_case("parse_version_triplet: overflow -> error", ok_vm5); ok_all &= ok_vm5;

    /* semver range: caret */
    semver_range_t r = {0};
    rc = parse_semver_range("^1.2.3", &r);
    int ok_caret = (rc == 0 && r.has_low && r.has_high && eq_triplet(r.low, 1,2,3) && eq_triplet(r.high, 2,0,0));
    print_case("parse_semver_range: '^1.2.3' -> [1.2.3,2.0.0)", ok_caret); ok_all &= ok_caret;

    /* semver range: tilde */
    memset(&r, 0, sizeof(r));
    rc = parse_semver_range("~1.2.3", &r);
    int ok_tilde = (rc == 0 && r.has_low && r.has_high && eq_triplet(r.low,1,2,3) && eq_triplet(r.high,1,3,0));
    print_case("parse_semver_range: '~1.2.3' -> [1.2.3,1.3.0)", ok_tilde); ok_all &= ok_tilde;

    memset(&r, 0, sizeof(r));
    rc = parse_semver_range("~1", &r);
    int ok_tilde_major = (rc == 0 && r.has_low && r.has_high && eq_triplet(r.low,1,0,0) && eq_triplet(r.high,2,0,0));
    print_case("parse_semver_range: '~1' -> [1.0.0,2.0.0)", ok_tilde_major); ok_all &= ok_tilde_major;

    memset(&r, 0, sizeof(r));
    rc = parse_semver_range("~1.0", &r);
    int ok_tilde_minor = (rc == 0 && r.has_low && r.has_high && eq_triplet(r.low,1,0,0) && eq_triplet(r.high,1,1,0));
    print_case("parse_semver_range: '~1.0' -> [1.0.0,1.1.0)", ok_tilde_minor); ok_all &= ok_tilde_minor;

    /* semver range: comparator pair */
    memset(&r, 0, sizeof(r));
    rc = parse_semver_range(">=1.2.3 <2.0.0", &r);
    int ok_comp = (rc == 0 && r.has_low && r.has_high);
    print_case("parse_semver_range: '>=1.2.3 <2.0.0' parsed", ok_comp); ok_all &= ok_comp;

    version_triplet_t t = {0};
    t.major=1; t.minor=2; t.patch=3; int in1 = semver_in_range(&t, &r);
    t.major=1; t.minor=9; t.patch=9; int in2 = semver_in_range(&t, &r);
    t.major=2; t.minor=0; t.patch=0; int out1 = semver_in_range(&t, &r);
    int ok_comp_bounds = (in1==1 && in2==1 && out1==0);
    print_case("semver_in_range within '>=1.2.3 <2.0.0' bounds", ok_comp_bounds); ok_all &= ok_comp_bounds;

    /* semver range: <= single comparator */
    memset(&r, 0, sizeof(r));
    rc = parse_semver_range("<=1.2.3", &r);
    int ok_le = (rc == 0 && r.has_high && !r.has_low);
    print_case("parse_semver_range: '<=1.2.3' parsed", ok_le); ok_all &= ok_le;
    t.major=1; t.minor=2; t.patch=3; int in3 = semver_in_range(&t, &r);
    t.major=1; t.minor=2; t.patch=4; int out2 = semver_in_range(&t, &r);
    int ok_le_bounds = (in3==1 && out2==0);
    print_case("semver_in_range for '<=1.2.3' bounds", ok_le_bounds); ok_all &= ok_le_bounds;

    /* semver range: star */
    memset(&r, 0, sizeof(r));
    rc = parse_semver_range("1.*", &r);
    int ok_star = (rc == 0 && r.has_low && r.has_high && eq_triplet(r.low,1,0,0) && eq_triplet(r.high,2,0,0));
    print_case("parse_semver_range: '1.*' -> [1.0.0,2.0.0)", ok_star); ok_all &= ok_star;

    /* malformed semver ranges */
    rc = parse_semver_range(">=1.2.3 2.0.0", &r); /* second token missing operator */
    int ok_bad_pair = (rc != 0);
    print_case("parse_semver_range: '>=1.2.3 2.0.0' -> error", ok_bad_pair); ok_all &= ok_bad_pair;

    rc = parse_semver_range("1..2", &r);
    int ok_bad_ver = (rc != 0);
    print_case("parse_semver_range: '1..2' -> error", ok_bad_ver); ok_all &= ok_bad_ver;

    rc = parse_semver_range("abc", &r);
    int ok_bad_str = (rc != 0);
    print_case("parse_semver_range: 'abc' -> error", ok_bad_str); ok_all &= ok_bad_str;

    rc = parse_semver_range("> 1.2.3", &r); /* operator separated by space is unsupported */
    int ok_op_space = (rc != 0);
    print_case("parse_semver_range: '> 1.2.3' -> error", ok_op_space); ok_all &= ok_op_space;

    return ok_all ? 0 : 1;
}


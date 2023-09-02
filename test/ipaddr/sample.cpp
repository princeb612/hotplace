/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;

static bool determine (ipaddr_acl* acl, const char* ip, bool expect)
{
    return_t ret = errorcode_t::success;
    bool check = false;

    ret = acl->determine (ip, check);
    printf ("check ip %s [%d]\n", ip, check ? 1 : 0);
    if (expect != check) {
        ret = errorcode_t::internal_error;
    }
    _test_case.test (ret, __FUNCTION__, "access control %s -> %d", ip, expect ? 1 : 0);
    return check;
}

void test1 ()
{
    //return_t ret = errorcode_t::success;
    ipaddr_acl acl;

    //return_t ret = errorcode_t::success;

    acl.add_rule ("127.0.0.1", true);
    acl.add_rule ("10.20.15.25", true);
    acl.add_rule ("10.20.13.25", 24, false);
    acl.add_rule ("::1", 128, true);
    acl.add_rule ("3ffe:ffff:0:f101::1", 64, true);

    // single true, but range false -> determin return false
    acl.add_rule ("10.20.1.125", true);
    acl.add_rule ("10.20.1.25", "10.20.2.10", false);

    acl.setmode (ipaddr_acl_t::whitelist);
    printf ("white list mode\n");

    determine (&acl, "127.0.0.1", true);
    determine (&acl, "10.20.15.24", false);
    determine (&acl, "10.20.13.2", false);
    determine (&acl, "10.20.1.224", false);
    determine (&acl, "10.20.1.125", false);
#ifdef SUPPORT_IPV6
    determine (&acl, "::1", true);
    determine (&acl, "0:0:0:0:0:0:0:1", true);
    determine (&acl, "3ffe:ffff:0:f101::ffff", true);
    determine (&acl, "3ffe:ffff:0:f101:1234::ffff", true);
    determine (&acl, "3ffe:ffff:0:f102::ffff", false);
    determine (&acl, "::1", true);
#endif

    acl.setmode (ipaddr_acl_t::blacklist);
    printf ("black list mode\n");

    determine (&acl, "127.0.0.1", true);
    determine (&acl, "10.20.15.24", true);
    determine (&acl, "10.20.13.2", false);
    determine (&acl, "10.20.1.224", false);
    determine (&acl, "10.20.1.125", false);
#ifdef SUPPORT_IPV6
    determine (&acl, "0:0:0:0:0:0:0:1", true);
    determine (&acl, "::1", true);
#endif
}

int pad_bytes (int i)
{
    int ret = 0;

    if (i < 10) {
        ret = 2;
    } else if (i < 100) {
        ret = 1;
    } else {
        ret = 0;
    }
    return ret;
}

void test2 ()
{
    printf ("%s\n", __FUNCTION__);

    ipaddr_acl acl;
    ansi_string stream;
    const char* address = "12.34.56.78";
    int family = 0;
    uint32 ipv4 = 0;

    ipv4 = acl.convert_addr (address, family);

    stream.printf ("%08x\n", ipv4);
    printf ("%s", stream.c_str ());
    stream.clear ();

    uint32 mask = 0;
    uint32 i = 0;
    for (i = 0; i <= 32; i++) {
        mask = t_cidr_subnet_mask<uint32> (i);
        std::string pad ("   ", pad_bytes (i));
        stream.printf ("%s/%d%s %08x & %08x => %08x ~ %08x\n",
                       address, i, pad.c_str (), (ipv4), (mask), (ipv4 & mask), ((ipv4 & mask) | ~mask));
    }
    printf ("%s", stream.c_str ());
}

void test3 ()
{
#if defined SUPPORT_IPV6
    printf ("%s\n", __FUNCTION__);

    ipaddr_acl acl;
    ansi_string stream;
    const char* address = "3ffe:ffff:0:f101::1";
    int family = 0;

    ipaddr_t ipv6 = acl.convert_addr (address, family);

    stream.printf ("%I128x\n", ipv6);
    printf ("%s", stream.c_str ());
    stream.clear ();

    ipaddr_t mask = 0;
    //uint cidr = 0;
    uint i = 0;
    for (i = 0; i <= 128; i++) {
        mask = t_cidr_subnet_mask<ipaddr_t> (i);
        std::string pad ("   ", pad_bytes (i));
        stream.printf ("%s/%d%s %032I128x & %032I128x => %032I128x ~ %032I128x\n",
                       address, i, pad.c_str (), (ipv6), (mask), (ipv6 & mask), ((ipv6 & mask) | ~mask));
    }
    printf ("%s", stream.c_str ());

    _test_case.assert (true, __FUNCTION__, "IPv6 supported");
#else
    _test_case.test (errorcode_t::not_supported, __FUNCTION__, "IPv6 not supported");
#endif
}

int main ()
{
    _test_case.begin ("smart pointer");

    test1 ();
    test2 ();
    test3 ();

    _test_case.report (5);
    return _test_case.result ();
}

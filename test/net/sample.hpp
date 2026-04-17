/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_NET__
#define __HOTPLACE_TEST_NET__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/net/hpack/test.hpp>
#include <hotplace/test/net/http/test.hpp>
#include <hotplace/test/net/qpack/test.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string url;
    int mode;
    int connect;

    OPTION() : CMDLINEOPTION(), url("https://localhost:9000/"), mode(0), connect(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern std::list<std::function<void(void)>> _cases;

// HTTP
void testcase_http();
void testcase_http2();
void testcase_http2_frame();

// ipaddr
void testcase_acl();

// HPACK

void testcase_huffman();
void testcase_rfc7541();
void testcase_h2();

// QPACK

void testcase_capacity();
void testcase_qpack_stream();
void testcase_rfc9204();

#endif

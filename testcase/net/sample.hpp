/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_NET__
#define __HOTPLACE_TEST_NET__

#include <hotplace/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string url;
    int mode;
    int connect;

    OPTION() : CMDLINEOPTION(), url("https://localhost:9000/"), mode(0), connect(0) {}
};

extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

// hpack
extern t_shared_instance<hpack_encoder> encoder;
void dump_hpack_session_routine(const char* stream, size_t size);

// http
struct testvector_http_t {
    tls_direction_t dir;
    const char* desc;
    const char* frame;
};
extern const testvector_http_t testvector_h2frame[];
extern const size_t sizeof_testvector_h2;

// qpack
void dump_qpack_session_routine(const char* stream, size_t size);
void test_expect(binary_t& bin, const char* expect, const char* func, const char* text, ...);
void test_dump(binary_t& bin, const char* text, ...);

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

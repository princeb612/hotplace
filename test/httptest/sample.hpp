/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_HTTPTEST__
#define __HOTPLACE_TEST_HTTPTEST__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string url;
    int mode;
    int connect;

    OPTION() : CMDLINEOPTION(), url("https://localhost:9000/"), mode(0), connect(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

struct testvector_http_t {
    tls_direction_t dir;
    const char* desc;
    const char* frame;
};

extern const testvector_http_t testvector_h2frame[];
extern const size_t sizeof_testvector_h2;

void test_http();
void test_http2_frame();
void test_http2();

#endif

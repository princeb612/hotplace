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

void test_uri();
void test_request();
void test_response_compose();
void test_response_parse();
void test_uri_form_encoded_body_parameter();
void test_uri2();
void test_escape_url();
void test_basic_authentication();
void test_digest_access_authentication(const char* alg = nullptr, unsigned long* ossl_minver = nullptr);
void test_rfc_digest_example();
void test_documents();
void test_get_tlsclient();
void test_get_httpclient();
void test_bearer_token();
void test_http2_frame();
void test_http2();

#endif

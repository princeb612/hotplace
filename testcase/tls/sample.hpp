/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TLS__
#define __HOTPLACE_TEST_TLS__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int keylog;
    int test_ffdhe;
    binary_t clienthello;

    OPTION() : CMDLINEOPTION(), keylog(0), test_ffdhe(0) {}
};

struct TLS_OPTION {
    uint16 version;
    std::string cipher_suite;
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

return_t dump_record(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin, bool expect = true);
return_t dump_handshake(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin);
void test_keycalc(tls_session* session, tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect);
void test_transcript_hash(tls_session* session, const binary_t& expect);
void direction_string(tls_direction_t dir, int send, std::string& s);
void do_cross_check_keycalc(tls_session* clisession, tls_session* svrsession, tls_secret_t secret, const char* secret_name);

return_t construct_record_fragmented(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func);
return_t construct_record_fragmented(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func);

// xargs.org
void testcase_understand_tls13();
void testcase_understand_tls12();
void testcase_understand_dtls();

// RFC
void testcase_rfc8448_2();
void testcase_rfc8448_3(tls_session* rfc8448_session);
void testcase_rfc8448_4(tls_session* rfc8448_session);
void testcase_rfc8448_5();
void testcase_rfc8448_6();
void testcase_rfc8448_7();

void testcase_pre_master_secret();

void testcase_tls12_aead();
void testcase_mlkem_encoding();

void testcase_testvector_pcap();

void testcase_dtls_record_arrange();

void testcase_construct_tls();
void testcase_construct_dtls13();
void testcase_construct_dtls12_1();
void testcase_construct_dtls12_2();
void testcase_resource();

void testcase_helloretryrequest();

void testcase_alert();

void dump_clienthello();

#endif

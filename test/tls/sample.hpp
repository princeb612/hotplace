#ifndef __HOTPLACE_TEST_TLS__
#define __HOTPLACE_TEST_TLS__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

struct OPTION {
    int verbose;
    int debug;
    int trace_level;
    int keylog;
    int log;
    int time;
    binary_t clienthello;

    OPTION() : verbose(0), debug(0), trace_level(0), keylog(0), log(0), time(0) {
        // do nothing
    }
    void enable_debug() {
        verbose = 1;
        debug = 1;
    }
};

struct TLS_OPTION {
    uint16 version;
    std::string cipher_suite;
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

extern tls_session rfc8448_session;
extern tls_session rfc8448_session2;

return_t dump_record(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin, bool expect = true);
return_t dump_handshake(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin);
void test_keycalc(tls_session* session, tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect);
void test_transcript_hash(tls_session* session, const binary_t& expect);
void direction_string(tls_direction_t dir, int send, std::string& s);
void do_cross_check_keycalc(tls_session* clisession, tls_session* svrsession, tls_secret_t secret, const char* secret_name);

return_t construct_record_fragmented(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func);
return_t construct_record_fragmented(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func);

// xargs.org
void test_tls13_xargs_org();
void test_tls12_xargs_org();
void test_dtls_xargs_org();

struct pcap_testvector {
    tls_direction_t dir;
    const char* desc;
    const char* record;
};
void play_pcap(tls_session* session, const pcap_testvector* testvector, size_t size);

extern const pcap_testvector pcap_tls13_aes128gcm_sha256[];
extern const size_t sizeof_pcap_tls13_aes128gcm_sha256;
extern const pcap_testvector pcap_tls13_aes256gcm_sha384[];
extern const size_t sizeof_pcap_tls13_aes256gcm_sha384;
extern const pcap_testvector pcap_tls13_aes128ccm_sha256[];
extern const size_t sizeof_pcap_tls13_aes128ccm_sha256;
extern const pcap_testvector pcap_tls13_chacha20_poly1305[];
extern const size_t sizeof_pcap_tls13_chacha20_poly1305;
extern const pcap_testvector pcap_tls12etm_aes128cbc_sha256[];
extern const size_t sizeof_pcap_tls12etm_aes128cbc_sha256;
extern const pcap_testvector pcap_tls12mte_aes128cbc_sha256[];
extern const size_t sizeof_pcap_tls12mte_aes128cbc_sha256;
extern const pcap_testvector capture_tls12_aes128gcm_sha256[];
extern const size_t sizeof_capture_tls12_aes128gcm_sha256;
extern const pcap_testvector capture_tls12_chacha20poly1305_sha256[];
extern const size_t sizeof_capture_tls12_chacha20poly1305_sha256;
extern const pcap_testvector pcap_dtls12[];
extern const size_t sizeof_pcap_dtls12;
extern const pcap_testvector pcap_dtls12_mtu1500[];
extern const size_t sizeof_pcap_dtls12_mtu1500;
extern const pcap_testvector pcap_dtls12_aes128gcm[];
extern const size_t sizeof_pcap_dtls12_aes128gcm;
extern const pcap_testvector pcap_tls13_http1_aes128gcm_sha256[];
extern const size_t sizeof_pcap_tls13_http1_aes128gcm_sha256;
extern const pcap_testvector pcap_tls13_http2_aes128gcm_sha256[];
extern const size_t sizeof_pcap_tls13_http2_aes128gcm_sha256;
extern const pcap_testvector pcap_curl_http1_tls12[];
extern const size_t sizeof_pcap_curl_http1_tls12;

// RFC
void test_rfc8448_2();
void test_rfc8448_3();
void test_rfc8448_4();
void test_rfc8448_5();
void test_rfc8448_6();
void test_rfc8448_7();

void test_use_pre_master_secret();

void test_tls12_aead();
void test_pcap_tls13();
void test_pcap_tls12();
void test_pcap_dtls12();
void test_pcap_tls13_http1();

void test_dtls_record_arrange();

void test_construct_tls();
void test_construct_dtls13();
void test_construct_dtls12_1();
void test_construct_dtls12_2();
void test_validate();

void dump_clienthello();

void test_helloretryrequest();

void test_alert();

void test_pcap_tls13_http1();

#endif

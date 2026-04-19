/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_QUIC__
#define __HOTPLACE_TEST_QUIC__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

enum test_flag_t {
    test_flag_quic = 1,
    test_flag_pcap = 2,
};

struct OPTION : public CMDLINEOPTION {
    int mode;
    int flags;
    int keylog;
    std::string content;

    OPTION() : CMDLINEOPTION(), mode(0), flags(0) {}
    void set(int m, const char* param) {
        mode = m;
        content = param;
    }
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

struct testvector_initial_packet {
    const char* text;
    const char* func;
    const char* odcid;
    const char* dcid;
    const char* scid;
    const char* token;
    const char* expect_unprotected_header;
    const char* expect_protected_header;
    const char* frame;
    const char* expect_result;
    tls_direction_t dir;
    bool pad;
    size_t resize;
    uint32 pn;
    uint8 pn_length;
    size_t length;
};

struct testvector_retry_packet {
    const char* text;
    const char* func;
    const char* odcid;
    const char* dcid;
    const char* scid;
    const char* token;
    const char* expect_result;
    const char* expect_tag;
    tls_direction_t dir;
};

/**
 * wireshark http3.pcapng
 */
enum prot_t : uint8 {
    prot_quic = 1,
    prot_tls13 = 2,
    prot_http3 = 3,
};

struct testvector_http3_t {
    tls_direction_t dir;
    prot_t prot;
    const char* desc;
    const char* frame;
    int debug;
};

extern const testvector_http3_t pcap_http3[];
extern const size_t sizeof_pcap_http3;

std::string direction_string(tls_direction_t dir);
void test_rfc_9001_construct_initial(testvector_initial_packet* item, tls_session* session);
void test_rfc_9001_send_initial(testvector_initial_packet* item, tls_session* session);
void test_rfc_9001_retry(testvector_retry_packet* item, tls_session* session);

void testcase_understand_quic();

// QUIC Version 1
void testcase_rfc_9000();

void testcase_rfc_9001();

// QUIC Version 2
void testcase_rfc_9369();

// pcap
void testcase_pcap_http3();
// construct
void testcase_construct_1rtt();
void testcase_construct_quic();

#endif

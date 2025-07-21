#ifndef __HOTPLACE_TEST_QUIC__
#define __HOTPLACE_TEST_QUIC__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

enum test_flag_t {
    test_flag_quic = 1,
    test_flag_pcap = 2,
};

typedef struct _OPTION {
    int verbose;
    int debug;
    int trace_level;
    int log;
    int time;
    int mode;
    int flags;
    int keylog;
    std::string content;

    _OPTION() : verbose(0), debug(0), trace_level(0), log(0), time(0), mode(0), flags(0) {
        // do nothing
    }
    void set(int m, const char* param) {
        mode = m;
        content = param;
    }
    void enable_debug() {
        verbose = 1;
        debug = 1;
    }
} OPTION;

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

// QUIC Version 1
void test_rfc_9000_a1();
void test_rfc_9000_a2();
void test_rfc_9000_a3();

void test_rfc_9001_construct_initial(testvector_initial_packet* item, tls_session* session);
void test_rfc_9001_send_initial(testvector_initial_packet* item, tls_session* session);
void test_rfc_9001_retry(testvector_retry_packet* item, tls_session* session);

void test_rfc_9001_section4();
void test_rfc_9001_a1();
void test_rfc_9001_a2();
void test_rfc_9001_a3();
void test_rfc_9001_a4();
void test_rfc_9001_a5();

void test_quic_xargs_org();

// QUIC Version 2
void test_rfc_9369_a1();
void test_rfc_9369_a2();
void test_rfc_9369_a3();
void test_rfc_9369_a4();
void test_rfc_9369_a5();

// pcap
void test_pcap_quic();
// QUIC Frame
void test_quic_frame();
// construct
void test_construct_quic();

#endif

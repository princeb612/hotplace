#ifndef __HOTPLACE_TEST_QUIC__
#define __HOTPLACE_TEST_QUIC__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;
    int mode;
    std::string content;

    _OPTION() : verbose(0), debug(0), log(0), time(0), mode(0) {
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

void test_rfc_9000_a1();
void test_rfc_9000_a2();
void test_rfc_9000_a3();
void test_rfc_9001_initial(testvector_initial_packet* item, tls_session* session);
void test_rfc_9001_section4();
void test_rfc_9001_a1();
void test_rfc_9001_a2();
void test_rfc_9001_a3();
void test_rfc_9001_a4();
void test_rfc_9001_a5();
void test_quic_xargs_org();

#endif

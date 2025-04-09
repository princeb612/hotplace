#ifndef __HOTPLACE_TEST_PAYLOAD__
#define __HOTPLACE_TEST_PAYLOAD__

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

    _OPTION() : verbose(0), debug(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_payload_write();
void test_payload_read();
void test_uint24();
void test_group();
void test_payload_uint24();
void test_http2_frame();
void test_quic_integer();
void test_uint48();

#endif

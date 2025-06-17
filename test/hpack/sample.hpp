#ifndef __HOTPLACE_TEST_HPACK__
#define __HOTPLACE_TEST_HPACK__

#include <signal.h>
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
extern t_shared_instance<hpack_encoder> encoder;

void dump_hpack_session_routine(const std::string& name, const std::string& value);

void test_huffman_codes();
void test_rfc7541_c_1();
void test_rfc7541_c_2();
void test_rfc7541_c_3();
void test_rfc7541_c_4();
void test_rfc7541_c_5();
void test_rfc7541_c_6();

void test_h2_header_frame();

#endif

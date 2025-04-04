#ifndef __HOTPLACE_TEST_CBOR__
#define __HOTPLACE_TEST_CBOR__

#include <math.h>
#include <stdio.h>

#include <deque>
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

    std::string content;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_rfc7049_table4_1();
void test_rfc7049_table4_2();

void test_parse();

#endif

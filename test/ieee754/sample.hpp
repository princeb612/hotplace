#ifndef __HOTPLACE_TEST_IEEE754__
#define __HOTPLACE_TEST_IEEE754__

#include <math.h>
#include <stdio.h>

#include <functional>
#include <iostream>
#include <sdk/sdk.hpp>
#include <string>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_ieee754();
void test_frexp();
void test_basic_stream();
void test_as_small_as_possible();

#endif

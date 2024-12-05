#ifndef __HOTPLACE_TEST_RANDOM__
#define __HOTPLACE_TEST_RANDOM__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_random();
void test_nonce();
void test_token();

#endif

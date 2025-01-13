#ifndef __HOTPLACE_TEST_CRYPTOKEY__
#define __HOTPLACE_TEST_CRYPTOKEY__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_crypto_key();
void test_eckey_compressed();
void test_ffdhe();

#endif

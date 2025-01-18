#ifndef __HOTPLACE_TEST_STREAM__
#define __HOTPLACE_TEST_STREAM__

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

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_consolecolor();
void test_dumpmemory();
void test_i128();
void test_sprintf();
void test_vprintf();
void test_stream();
void test_stream_getline();
void test_stream_stdmap();
void test_vtprintf();
void test_autoindent();

#endif

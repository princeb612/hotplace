#ifndef __HOTPLACE_TEST_CMDLINE__
#define __HOTPLACE_TEST_CMDLINE__

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

    std::string infile;
    std::string outfile;
    bool keygen;

    _OPTION() : verbose(0), debug(0), log(0), time(0), keygen(false){};
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test1();

#endif

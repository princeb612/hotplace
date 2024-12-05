#ifndef __HOTPLACE_TEST_UDPSERVER__
#define __HOTPLACE_TEST_UDPSERVER__

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
    uint16 port;

    _OPTION() : verbose(0), log(0), time(0), port(9000) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void run_server();

#endif

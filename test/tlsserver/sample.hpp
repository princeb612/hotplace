#ifndef __HOTPLACE_TEST_TLSSERVER__
#define __HOTPLACE_TEST_TLSSERVER__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

enum option_flag_t {
    option_flag_allow_tls13 = (1 << 0),
    option_flag_allow_tls12 = (1 << 1),
};

typedef struct _OPTION {
    int run;
    int verbose;
    int debug;
    int log;
    int time;
    uint16 port;
    uint32 flags;

    _OPTION() : run(0), verbose(0), debug(0), log(0), time(0), port(9000), flags(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void run_server();

#endif

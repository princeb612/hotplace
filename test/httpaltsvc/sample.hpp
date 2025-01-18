#ifndef __HOTPLACE_TEST_HTTPALTSVC__
#define __HOTPLACE_TEST_HTTPALTSVC__

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int port_h1;
    int port_h2;
    int port_h3;
    int packetsize;
    int verbose;
    int debug;
    int log;
    int time;

    _OPTION() : port_h1(9000), port_h2(9001), port_h3(9002), packetsize(1 << 16), verbose(0), debug(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<hpack_encoder> encoder;
extern t_shared_instance<http_server> _http_server1;
extern t_shared_instance<http_server> _http_server2;

void run_server();

#endif

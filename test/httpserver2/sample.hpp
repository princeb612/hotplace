#ifndef __HOTPLACE_TEST_HTTPSERVER2__
#define __HOTPLACE_TEST_HTTPSERVER2__

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int port;
    int port_tls;
    int content_encoding;
    int verbose;
    int debug;
    int log;
    int time;

    _OPTION() : port(8080), port_tls(9000), content_encoding(0), verbose(0), debug(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

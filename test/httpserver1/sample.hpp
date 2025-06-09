#ifndef __HOTPLACE_TEST_HTTPSERVER__
#define __HOTPLACE_TEST_HTTPSERVER__

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int run;
    int port;
    int port_tls;
    int content_encoding;
    int trial;
    int keylog;
    int verbose;
    int debug;
    int trace_level;
    int log;
    int time;

    _OPTION() : run(0), port(8080), port_tls(9000), content_encoding(0), trial(0), keylog(0), verbose(0), debug(0), trace_level(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

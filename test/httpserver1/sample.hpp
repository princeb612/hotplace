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
    int port;
    int port_tls;
    int verbose;
    int log;
    int time;

    _OPTION() : port(8080), port_tls(9000), verbose(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern t_shared_instance<http_server> _http_server;

void debug_handler(trace_category_t category, uint32 event, stream_t *s);
void run_server();

#endif

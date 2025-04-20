#ifndef __HOTPLACE_TEST_CBOR__
#define __HOTPLACE_TEST_CBOR__

#include <math.h>
#include <stdio.h>

#include <deque>
#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

enum {
    flag_debug_tls_inside = 1 << 0,
    flag_http = 1 << 1,
    flag_allow_tls12 = 1 << 2,
    flag_allow_tls13 = 1 << 3,
    flag_enable_etm = 1 << 4,
};

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;

    int bufsize;
    std::string address;
    uint16 port;
    uint16 prot;
    uint16 count;
    uint16 flags;
    std::string message;

    _OPTION() : verbose(0), debug(0), log(0), time(0), bufsize(1500), address("127.0.0.1"), port(9000), prot(0), count(1), flags(0), message("hello") {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void tcp_client();
void udp_client();
void tls_client();
void dtls_client();

// insecure simple implementation to understand TLS
void async_tls_client();
void async_dtls_client();

#endif

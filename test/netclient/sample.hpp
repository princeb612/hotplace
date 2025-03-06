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
    std::string message;

    _OPTION() : verbose(0), debug(0), log(0), time(0), bufsize(1500), address("127.0.0.1"), port(9000), prot(0), count(1), message("hello") {
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

void tls_client2();

#endif

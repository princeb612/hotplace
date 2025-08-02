#ifndef __HOTPLACE_TEST_NETCLIENT__
#define __HOTPLACE_TEST_NETCLIENT__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

enum {
    option_flag_debug_tls_inside = 1 << 0,
    option_flag_http = 1 << 1,
    option_flag_allow_tls12 = 1 << 2,
    option_flag_allow_tls13 = 1 << 3,
    option_flag_keylog = 1 << 5,
};

struct OPTION : public CMDLINEOPTION {
    int bufsize;
    std::string address;
    uint16 port;
    uint16 prot;
    uint16 count;
    uint16 wto;
    uint16 flags;
    std::string message;

    OPTION() : CMDLINEOPTION(), bufsize(1500), port(9000), prot(0), count(1), wto(1000), flags(0) {
        address = "127.0.0.1";
        message = "hello";
    }
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void tcp_client();
void udp_client();
void tls_client();
void dtls_client();

// insecure simple implementation to understand TLS
void tls_client2();
void dtls_client2();

#endif

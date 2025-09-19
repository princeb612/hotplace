#ifndef __HOTPLACE_TEST_HTTPAUTH__
#define __HOTPLACE_TEST_HTTPAUTH__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int run;
    int port;
    int port_tls;
    int h2;
    int keylog;

    OPTION() : CMDLINEOPTION(), run(0), port(8080), port_tls(9000), h2(0), keylog(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<hpack_encoder> encoder;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

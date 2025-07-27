#ifndef __HOTPLACE_TEST_HTTPSERVER2__
#define __HOTPLACE_TEST_HTTPSERVER2__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int run;
    int port;
    int port_tls;
    int content_encoding;
    int trial;
    int keylog;
    std::string cs;

    OPTION() : CMDLINEOPTION(), run(0), port(8080), port_tls(9000), content_encoding(0), trial(0), keylog(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

#ifndef __HOTPLACE_TEST_TCPSERVER__
#define __HOTPLACE_TEST_TCPSERVER__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int run;
    uint16 port;

    OPTION() : CMDLINEOPTION(), run(0), port(9000) {
        // do nothing
    }
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void run_server();

#endif

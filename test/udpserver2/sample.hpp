/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_UDPSERVER__
#define __HOTPLACE_TEST_UDPSERVER__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int run;
    uint16 port;

    OPTION() : CMDLINEOPTION(), run(0), port(9000) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void run_server();

#endif

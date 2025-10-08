/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_HTTPALTSVC__
#define __HOTPLACE_TEST_HTTPALTSVC__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int run;
    int port_h1;
    int port_h2;
    int port_h3;
    int packetsize;

    OPTION() : CMDLINEOPTION(), run(0), port_h1(9000), port_h2(9001), port_h3(9002), packetsize(1 << 16) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<hpack_encoder> encoder;
extern t_shared_instance<http_server> _http_server1;
extern t_shared_instance<http_server> _http_server2;

void run_server();

#endif

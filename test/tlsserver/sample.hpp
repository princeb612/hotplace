/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TLSSERVER__
#define __HOTPLACE_TEST_TLSSERVER__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

enum option_flag_t {
    option_flag_allow_tls13 = (1 << 0),
    option_flag_allow_tls12 = (1 << 1),
    option_flag_trial = (1 << 2),
    option_flag_keylog = (1 << 3),
};

struct OPTION : public CMDLINEOPTION {
    int run;
    uint16 port;
    uint32 flags;
    std::string cs;

    OPTION() : CMDLINEOPTION(), run(0), port(9000), flags(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void run_server();

#endif

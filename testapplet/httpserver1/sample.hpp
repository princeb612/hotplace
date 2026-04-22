/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TESTAPPLET_HTTPSERVER__
#define __HOTPLACE_TESTAPPLET_HTTPSERVER__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

enum option_flag_t {
    option_flag_trial = (1 << 1),
    option_flag_keylog = (1 << 2),
    option_flag_content_encoding = (1 << 3),
    option_flag_cert_rsa = (1 << 4),
    option_flag_cert_ecdsa = (1 << 5),
    option_flag_cert_mldsa = (1 << 6),
};
struct OPTION : public CMDLINEOPTION {
    int run;
    int port;
    int port_tls;
    uint32 flags;
    std::string cs;

    OPTION() : CMDLINEOPTION(), run(0), port(8080), port_tls(9000), flags(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

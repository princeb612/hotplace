/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_APPLET_HTTPSERVER2__
#define __HOTPLACE_TEST_APPLET_HTTPSERVER2__

#include <hotplace/test/test.hpp>

enum option_flag_t {
    option_flag_trial = (1 << 1),
    option_flag_keylog = (1 << 2),
    option_flag_content_encoding = (1 << 3),
};
struct OPTION : public CMDLINEOPTION {
    int run;
    int port;
    int port_tls;
    uint32 flags;
    std::string cs;
    std::string cert;

    OPTION() : CMDLINEOPTION(), run(0), port(8080), port_tls(9000), flags(0) {}
};

extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<http_server> _http_server;

void run_server();

#endif

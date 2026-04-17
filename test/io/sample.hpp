/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_IO__
#define __HOTPLACE_TEST_IO__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool flag_netlink;

    OPTION() : CMDLINEOPTION(), flag_netlink(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
extern std::list<std::function<void(void)>> _cases;

void testcase_parser();

void testcase_payload();
void testcase_payload_quic();

void testcase_mlfq();
void testcase_netlink();

#endif

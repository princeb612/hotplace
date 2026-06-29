/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TESTCASE_IO__
#define __HOTPLACE_TEST_TESTCASE_IO__

#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool flag_netlink;

    OPTION() : CMDLINEOPTION(), flag_netlink(false) {}
};

extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void testcase_payload();
void testcase_payload_quic();

void testcase_filestream();

void testcase_mlfq();
void testcase_netlink();

#endif

/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_IEEE754__
#define __HOTPLACE_TEST_IEEE754__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_ieee754();
void test_frexp();
void test_basic_stream();
void test_as_small_as_possible();

#endif

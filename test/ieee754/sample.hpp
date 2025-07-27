#ifndef __HOTPLACE_TEST_IEEE754__
#define __HOTPLACE_TEST_IEEE754__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

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

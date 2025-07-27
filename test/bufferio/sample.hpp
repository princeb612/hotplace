#ifndef __HOTPLACE_TEST_BUFFERIO__
#define __HOTPLACE_TEST_BUFFERIO__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_bufferio();
void test_bufferio2();

#endif

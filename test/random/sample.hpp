#ifndef __HOTPLACE_TEST_RANDOM__
#define __HOTPLACE_TEST_RANDOM__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_random();
void test_nonce();
void test_token();

#endif

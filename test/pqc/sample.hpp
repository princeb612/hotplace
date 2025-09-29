#ifndef __HOTPLACE_TEST_STREAM__
#define __HOTPLACE_TEST_STREAM__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_encode();
void test_kem();

#endif

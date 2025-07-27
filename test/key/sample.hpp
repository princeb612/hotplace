#ifndef __HOTPLACE_TEST_CRYPTOKEY__
#define __HOTPLACE_TEST_CRYPTOKEY__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_crypto_key();
void test_eckey_compressed();
void test_ffdhe();
void test_ffdhe_dh();
void test_der();
void test_dsa();

#endif

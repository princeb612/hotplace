#ifndef __HOTPLACE_TEST_KDF__
#define __HOTPLACE_TEST_KDF__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;
    bool test_slow_kdf;

    _OPTION() : verbose(0), log(0), time(0), test_slow_kdf(false) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_kdf_hkdf();
void test_kdf_pbkdf2_rfc6070();
void test_kdf_pbkdf2_rfc7914();
void test_kdf_scrypt_rfc7914();
void test_kdf_argon_rfc9106();
void test_kdf_extract_expand_rfc5869();
void test_ckdf_rfc4615();

#endif

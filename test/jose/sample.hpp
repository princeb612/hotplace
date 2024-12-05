#ifndef __HOTPLACE_TEST_JOSE__
#define __HOTPLACE_TEST_JOSE__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    bool verbose;
    int log;
    int time;

    bool dump_keys;

    _OPTION() : verbose(false), log(0), time(0), dump_keys(false) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void print_text(const char* text, ...);
void dump(const char* text, const std::string& value);
void dump_b64url(const char* text, const byte_t* addr, size_t size);
void dump_b64url(const char* text, const binary_t& bin);
void dump2(const char* text, std::string const str);
void dump2(const char* text, binary_t const bin);
void dump2(const char* text, const byte_t* addr, size_t size);
void dump_elem(const binary_t& source);
void dump_elem(const std::string& source);
void dump_crypto_key(crypto_key_object* key, void*);
return_t hash_stream(const char* algorithm, byte_t* stream, size_t size, binary_t& value);

void test_basic();
void test_rfc7515_A1();
void test_rfc7515_HS();
void test_rfc7515_A2();
void test_rfc7515_A3();
void test_rfc7515_A4();
void test_rfc7515_A5();
void test_rfc7515_A6();
void test_rfc7515_A7();
void test_rfc7515_bypem();
void test_rfc7515_bykeygen();
void key_match_test();
void test_rfc7516_A1_test();
void test_rfc7516_A1();
void test_rsa_oaep_256();
void test_rsa_oaep();
void test_rfc7516_A2();
void test_rfc7516_A3();
void test_rfc7516_A4();
void test_rfc7516_B();
void test_rfc7517_C();
void test_jwk();
void test_rfc7518_RSASSA_PSS();
int test_ecdh();
void test_rfc7518_C();
void test_rfc7520();
void test_rfc7520_6_nesting_sig_and_enc();
void test_jwe_flattened();
void test_jwe_json(jwe_t enc);
void test_jwk_thumbprint();
void test_rfc8037();
void test_okp();

#endif

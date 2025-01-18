#ifndef __HOTPLACE_TEST_HASH__
#define __HOTPLACE_TEST_HASH__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    bool verbose;
    bool debug;
    int log;
    int time;
    bool dump_keys;

    _OPTION() : verbose(false), debug(false), log(0), time(0), dump_keys(false) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_hash_routine(hash_t* hash_object, hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size);
return_t test_hash_routine(hash_t* hash_object, hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text);

void test_hash_algorithms();
void test_hmacsha_rfc4231();
void test_cmac_rfc4493();
uint32 test_hotp_rfc4226();
uint32 test_totp_rfc6238(hash_algorithm_t algorithm);
void test_transcript_hash();

#endif

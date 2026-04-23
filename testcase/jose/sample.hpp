/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_JOSE__
#define __HOTPLACE_TEST_JOSE__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;

    OPTION() : CMDLINEOPTION(), dump_keys(false) {}
};

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

void testcase_rfc7515();
void testcase_rfc7516();
void testcase_rfc7517();
void testcase_rfc7518();
void testcase_rfc7520();
void testcase_rfc7638();
void testcase_rfc8037();

#endif

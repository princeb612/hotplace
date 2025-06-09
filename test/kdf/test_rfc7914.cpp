/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_kdf_pbkdf2_rfc7914() {
    // RFC 7914 11.  Test Vectors for PBKDF2 with HMAC-SHA-256
    _test_case.begin("pbkdf2");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    openssl_kdf kdf;

    struct {
        const char* password;
        const char* salt;
        int c;
        int dlen;
        const char* expect;
    } vector[] = {
        {
            "passwd",
            "salt",
            1,
            64,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        },
        {
            "Password",
            "NaCl",
            80000,
            64,
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        },
    };

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        kdf.pbkdf2(result, hash_algorithm_t::sha2_256, vector[i].dlen, vector[i].password, str2bin(vector[i].salt), vector[i].c);

        if (option.verbose) {
            _logger->dump(result);
        }

        _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "RFC7914.pbkdf2 c = %i", vector[i].c);
    }
}

void test_kdf_scrypt_rfc7914() {
    // RFC 7914 12.  Test Vectors for scrypt
    _test_case.begin("scrypt (salt zero-length openssl 3.0 required)");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    openssl_kdf kdf;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    bool support = advisor->query_feature("scrypt");
    if (support) {
        // openssl-3.0
        struct {
            const char* password;
            const char* salt;
            int n;
            int r;
            int p;
            int dlen;
            const char* expect;
        } vector[] = {
            {
                "",
                "",  // openssl 1.1.1 - [crypto/kdf/scrypt.c @ 261] error:3407B06F:KDF routines:kdf_scrypt_derive:missing salt
                16,
                1,
                1,
                64,
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            },
            {
                "password",
                "NaCl",
                1024,
                8,
                16,
                64,
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            },
            {
                "pleaseletmein",
                "SodiumChloride",
                16384,
                8,
                1,
                64,
                "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            },
            {
                "pleaseletmein",
                "SodiumChloride",
                1048576,
                8,
                1,
                64,
                "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
            },
        };

        binary_t result;

        for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
            ret = kdf.scrypt(result, vector[i].dlen, vector[i].password, str2bin(vector[i].salt), vector[i].n, vector[i].r, vector[i].p);
            if (errorcode_t::success == ret) {
                if (option.verbose) {
                    _logger->dump(result);
                }
            }
            _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "scrypt");
        }
    } else {
        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "scrypt");
    }
}

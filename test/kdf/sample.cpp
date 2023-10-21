/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <hotplace/sdk/sdk.hpp>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;

return_t compare_binary(binary_t const& lhs, binary_t const& rhs) {
    return_t ret = errorcode_t::success;

    if (lhs != rhs) {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

void test_kdf_hkdf() {
    _test_case.begin("hkdf");

    return_t ret = errorcode_t::success;

    struct {
        const char* password;
        const char* salt;
        const char* info;
        int dlen;
        const char* expect;
    } vector[] = {
        {"secret", "salt", "label", 10, "2ac4369f525996f8de13"},
    };

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        kdf_hkdf(result, hash_algorithm_t::sha2_256, vector[i].dlen, convert(vector[i].password), convert(vector[i].salt), convert(vector[i].info));
        basic_stream bs;
        dump_memory(result, &bs);
        std::cout << bs.c_str() << std::endl;

        ret = compare_binary(base16_decode(vector[i].expect), result);
        _test_case.test(ret, __FUNCTION__, "hkdf");
    }
}

void test_kdf_pbkdf2_rfc6070() {
    _test_case.begin("pbkdf2");

    return_t ret = errorcode_t::success;

    // RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
    // 2.  PBKDF2 HMAC-SHA1 Test Vectors
    struct {
        const char* password;
        size_t size_password;
        const char* salt;
        size_t size_salt;
        int c;
        int dlen;
        const char* expect;
    } vector[] = {
        {"password", 8, "salt", 4, 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
        {"password", 8, "salt", 4, 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
        {"password", 8, "salt", 4, 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
        {"password", 8, "salt", 4, 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"},
        {"passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
        {"pass\0word", 9, "sa\0lt", 5, 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
    };

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        binary_t password;
        password.insert(password.end(), vector[i].password, vector[i].password + vector[i].size_password);
        binary_t salt;
        salt.insert(salt.end(), vector[i].salt, vector[i].salt + vector[i].size_salt);
        kdf_pbkdf2(result, hash_algorithm_t::sha1, vector[i].dlen, password, salt, vector[i].c);
        basic_stream bs;
        dump_memory(result, &bs);
        std::cout << bs.c_str() << std::endl;

        ret = compare_binary(base16_decode(vector[i].expect), result);
        _test_case.test(ret, __FUNCTION__, "RFC6070.pbkdf2 c = %i", vector[i].c);
    }
}

void test_kdf_pbkdf2_rfc7914() {
    // RFC 7914 11.  Test Vectors for PBKDF2 with HMAC-SHA-256
    _test_case.begin("pbkdf2");

    return_t ret = errorcode_t::success;

    struct {
        const char* password;
        const char* salt;
        int c;
        int dlen;
        const char* expect;
    } vector[] = {{"passwd", "salt", 1, 64,
                   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
                  {"Password", "NaCl", 80000, 64,
                   "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"}};

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        kdf_pbkdf2(result, hash_algorithm_t::sha2_256, vector[i].dlen, vector[i].password, convert(vector[i].salt), vector[i].c);
        basic_stream bs;
        dump_memory(result, &bs);
        std::cout << bs.c_str() << std::endl;

        ret = compare_binary(base16_decode(vector[i].expect), result);
        _test_case.test(ret, __FUNCTION__, "RFC7914.pbkdf2 c = %i", vector[i].c);
    }
}

void test_kdf_scrypt_rfc7914() {
    // RFC 7914 12.  Test Vectors for scrypt
    _test_case.begin("scrypt (salt zero-length openssl 3.0 required)");

    return_t ret = errorcode_t::success;

    struct {
        const char* password;
        const char* salt;
        int n;
        int r;
        int p;
        int dlen;
        const char* expect;
    } vector[] = {{// openssl 1.1.1
                   // [crypto/kdf/scrypt.c @ 261] error:3407B06F:KDF routines:kdf_scrypt_derive:missing salt
                   "", "", 16, 1, 1, 64,
                   "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
                  {"password", "NaCl", 1024, 8, 16, 64,
                   "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"},
                  {"pleaseletmein", "SodiumChloride", 16384, 8, 1, 64,
                   "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"},
                  {"pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64,
                   "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"}};

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        ret = kdf_scrypt(result, vector[i].dlen, vector[i].password, convert(vector[i].salt), vector[i].n, vector[i].r, vector[i].p);
        if (errorcode_t::success == ret) {
            basic_stream bs;
            dump_memory(result, &bs);
            std::cout << bs.c_str() << std::endl;

            ret = compare_binary(base16_decode(vector[i].expect), result);
        }
        _test_case.test(ret, __FUNCTION__, "scrypt");
    }
}

void test_kdf_argon_rfc9106() {
    _test_case.begin("argon2d,argon2i,argon2id");

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    struct {
        argon2_t mode;
        const char* password;
        const char* salt;
        const char* secret;
        const char* ad;
        const char* expect;
        const char* message;
    } vector[] = {
        {// 5.1.  Argon2d Test Vectors
         argon2_t::argon2d, "0101010101010101010101010101010101010101010101010101010101010101", "02020202020202020202020202020202", "0303030303030303",
         "040404040404040404040404", "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb", "RFC 9106 5.1.  Argon2d Test Vectors"},
        {// 5.2.  Argon2i Test Vectors
         argon2_t::argon2i, "0101010101010101010101010101010101010101010101010101010101010101", "02020202020202020202020202020202", "0303030303030303",
         "040404040404040404040404", "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8", "RFC 9106 5.2.  Argon2i Test Vectors"},
        {// 5.3.  Argon2id Test Vectors
         argon2_t::argon2id, "0101010101010101010101010101010101010101010101010101010101010101", "02020202020202020202020202020202", "0303030303030303",
         "040404040404040404040404", "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", "RFC 9106 5.3.  Argon2id Test Vectors"},
    };

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        binary_t derived;

        kdf_argon2(derived, vector[i].mode, 32, base16_decode(vector[i].password), base16_decode(vector[i].salt), base16_decode(vector[i].ad),
                   base16_decode(vector[i].secret));

        basic_stream bs;
        dump_memory(derived, &bs);
        std::cout << bs.c_str() << std::endl;

        return_t ret = errorcode_t::success;
        ret = compare_binary(derived, base16_decode(vector[i].expect));

        _test_case.test(ret, __FUNCTION__, "argon2id");
    }
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "argon2d,argon2i,argon2id at least openssl 3.2 required");
#endif
}

int main() {
    set_trace_option(trace_option_t::trace_bt);

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        test_kdf_hkdf();
        test_kdf_pbkdf2_rfc6070();
        test_kdf_pbkdf2_rfc7914();
        test_kdf_scrypt_rfc7914();
        test_kdf_argon_rfc9106();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _test_case.report(5);
    std::cout << "openssl 3 deprected bf, idea, seed" << std::endl;
    return _test_case.result();
}

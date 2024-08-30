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

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    bool test_slow_kdf;

    _OPTION() : verbose(0), test_slow_kdf(false) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_kdf_hkdf() {
    _test_case.begin("hkdf");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;

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
        kdf.hmac_kdf(result, hash_algorithm_t::sha2_256, vector[i].dlen, tobin(vector[i].password), tobin(vector[i].salt), tobin(vector[i].info));

        if (option.verbose) {
            _logger->dump(result);
        }

        _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "hkdf");
    }
}

void test_kdf_pbkdf2_rfc6070() {
    _test_case.begin("pbkdf2");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    openssl_kdf kdf;

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
        kdf.pbkdf2(result, hash_algorithm_t::sha1, vector[i].dlen, password, salt, vector[i].c);

        if (option.verbose) {
            _logger->dump(result);
        }

        _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "RFC6070.pbkdf2 c = %i", vector[i].c);
    }
}

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
    } vector[] = {{"passwd", "salt", 1, 64,
                   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
                  {"Password", "NaCl", 80000, 64,
                   "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"}};

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        kdf.pbkdf2(result, hash_algorithm_t::sha2_256, vector[i].dlen, vector[i].password, tobin(vector[i].salt), vector[i].c);

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
            {"",
             "",  // openssl 1.1.1 - [crypto/kdf/scrypt.c @ 261] error:3407B06F:KDF routines:kdf_scrypt_derive:missing salt
             16, 1, 1, 64, "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
            {"password", "NaCl", 1024, 8, 16, 64,
             "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"},
            {"pleaseletmein", "SodiumChloride", 16384, 8, 1, 64,
             "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"},
            {"pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64,
             "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"}};

        binary_t result;

        for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
            ret = kdf.scrypt(result, vector[i].dlen, vector[i].password, tobin(vector[i].salt), vector[i].n, vector[i].r, vector[i].p);
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

void test_kdf_argon_rfc9106() {
    _test_case.begin("argon2d,argon2i,argon2id");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    if (advisor->at_least_openssl_version(0x30200000L)) {
        // openssl-3.2
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

            kdf.argon2(derived, vector[i].mode, 32, base16_decode(vector[i].password), base16_decode(vector[i].salt), base16_decode(vector[i].ad),
                       base16_decode(vector[i].secret));

            if (option.verbose) {
                _logger->dump(derived);
            }

            _test_case.assert(derived == base16_decode(vector[i].expect), __FUNCTION__, "argon2id");
        }
    } else {
        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "argon2d,argon2i,argon2id at least openssl 3.2 required");
    }
}

void test_kdf_extract_expand_rfc5869() {
    _test_case.begin("KDF-Extract/Expand");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    // RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

    struct {
        const char* desc;
        const char* alg;
        int dlen;
        const char* ikm;
        const char* salt;
        const char* info;
        const char* prk;
        const char* okm;
    } expand_vector[] = {
        {
            "Test Case 1 - Basic test case with SHA-256",
            "sha256",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0x000102030405060708090a0b0c",
            "0xf0f1f2f3f4f5f6f7f8f9",
            "0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        {
            "Test Case 2 - Test with SHA-256 and longer inputs/outputs",
            "sha256",
            82,
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
            "48494a4b4c4d4e4f",
            "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
            "a8a9aaabacadaeaf",
            "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
            "f8f9fafbfcfdfeff",
            "0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87"
            "c14c01d5c1f3434f1d87",
        },
        {
            "Test Case 3 - Test with SHA-256 and zero-length salt/info",
            "sha256",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
        {
            "Test Case 4 - Basic test case with SHA-1",
            "sha1",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b",
            "0x000102030405060708090a0b0c",
            "0xf0f1f2f3f4f5f6f7f8f9",
            "0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
            "0x085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
        },
        {
            "Test Case 5 - Test with SHA-1 and longer inputs/outputs",
            "sha1",
            82,
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
            "48494a4b4c4d4e4f",
            "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
            "a8a9aaabacadaeaf",
            "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
            "f8f9fafbfcfdfeff",
            "0x8adae09a2a307059478d309b26c4115a224cfaf6",
            "0x0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c43"
            "00e2cff0d0900b52d3b4",
        },
        {
            "Test Case 6 - Test with SHA-1 and zero-length salt/info",
            "sha1",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "0xda8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
            "0x0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        },
        {
            "Test Case 7 - Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info",
            "sha1",
            42,
            "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "",
            "",
            "0x2adccada18779e7c2077ad2eb19d3f3e731385dd",
            "0x2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        },
    };

    int i = 0;
    basic_stream bs;
    for (i = 0; i < RTL_NUMBER_OF(expand_vector); i++) {
        // 2.2 Step 1: Extract
        //  PRK = HMAC-Hash(salt, IKM)
        binary_t prk;
        kdf.hmac_kdf_extract(prk, expand_vector[i].alg, base16_decode(expand_vector[i].salt), base16_decode(expand_vector[i].ikm));

        // dump_memory(prk, &bs);
        // printf("PRK\n%s\n", bs.c_str());

        // 2.3 Step 2: Expand
        //  HKDF-Expand(PRK, info, L) -> OKM
        binary_t okm;
        kdf.hkdf_expand(okm, expand_vector[i].alg, expand_vector[i].dlen, prk, base16_decode(expand_vector[i].info));

        if (option.verbose) {
            _logger->hdump("OKM", okm);
        }

        binary_t derived;
        kdf.hmac_kdf(derived, expand_vector[i].alg, expand_vector[i].dlen, base16_decode(expand_vector[i].ikm), base16_decode(expand_vector[i].salt),
                     base16_decode(expand_vector[i].info));

        if (option.verbose) {
            _logger->hdump("HKDF", derived);
        }

        _test_case.assert((okm == base16_decode(expand_vector[i].okm)), __FUNCTION__, "%s - RFC 5869 KDF_Extract, KDF_Expand", expand_vector[i].desc);
        _test_case.assert((okm == derived), __FUNCTION__, "%s - EVP_PKEY_derive", expand_vector[i].desc);
    }
}

// The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128
// (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)
void test_ckdf_rfc4615() {
    _test_case.begin("CMAC-based Extract-and-Expand Key Derivation Function (CKDF)");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;

    // RFC 4615 AES-CMAC-PRF-128
    // study step.1 CKDF_Extract
    struct {
        const char* desc;
        const char* salt;
        const char* ikm;
        const char* prk;
    } extract_vector[] = {
        {
            "Test Case 1",
            "000102030405060708090a0b0c0d0e0fedcb",
            "000102030405060708090a0b0c0d0e0f10111213",
            "84a348a4a45d235babfffc0d2b4da09a",
        },
        {
            "Test Case 2",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "980ae87b5f4c9c5214f5b6a8455e4c2d",
        },
        {
            "Test Case 3",
            "00010203040506070809",
            "000102030405060708090a0b0c0d0e0f10111213",
            "290d9e112edb09ee141fcf64c0b72f3d",
        },
        {
            "Test Case 4",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "",
            "bb1d6929e95937287fa37d129b756746",
        },
        {
            "Test Case 5",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "070a16b46b4d4144f79bdd9dd04a287c",
        },
        {
            "Test Case 6",
            "",
            "736563726574206b6579",
            "6f79b401ea761a0100b7ca60c178b69d",
        },
    };

    basic_stream bs;
    size_t i = 0;

    // study step.2 CKDF_Expand
    // study step.3 CKDF
    for (i = 0; i < RTL_NUMBER_OF(extract_vector); i++) {
        binary_t output;

        binary_t salt = base16_decode(extract_vector[i].salt);
        // If no salt is given, the 16-byte, all-zero value is used.
        if (0 == salt.size()) {
            salt.resize(128 >> 3);
        }

        // cmac_kdf_extract(output, crypt_algorithm_t::aes128, base16_decode(extract_vector[i].salt), base16_decode(extract_vector[i].ikm));
        kdf.cmac_kdf_extract(output, crypt_algorithm_t::aes128, salt, base16_decode(extract_vector[i].ikm));

        if (option.verbose) {
            _logger->dump(output);
        }

        _test_case.assert(output == base16_decode(extract_vector[i].prk), __FUNCTION__, "CKDF_Extract %s - RFC 4615 AES-CMAC-PRF-128", extract_vector[i].desc);
    }

    struct {
        const char* desc;
        int dlen;
        const char* salt;
        const char* ikm;
        const char* prk;
        const char* info;
        const char* okm;
    } expand_vector[] = {
        {
            "case 1",
            32,
            "",
            "736563726574206b6579",
            "6f79b401ea761a0100b7ca60c178b69d",
            "",
            "922da31d7e1955f06a56464b5feb7032f3e996295165f6c60e08ba432dd9058b",
        },
        {
            "case 2",
            256,
            "",
            "736563726574206b6579",
            "6f79b401ea761a0100b7ca60c178b69d",
            "696e666f20737472696e67",
            "6174e67212e1234b6e05bfd31043422c7ab6dc315db7d98d013ab332924b7fe90ae9a89d09c93be40ce525e0b6f0d37df38181913aa3d588f75a3594ef7a93acd791331e7929de8bc8"
            "c8a6ee2dd9960ec57fe159610676a7c118c4aac2d34a896edd3691f0e922a30eecc7b3ec3eaa9113d4ee518b0a4c7ed0b475dfbd07ee02a3470832da247ef3b07f9acd8ddbb7657369"
            "e1c52942fab211d47c440d6818f829cdd8dad84b825e1166cbdcdbb13904d6753de76070a145a8572496c28085679459d801f14449fbf3430a83685a4b8d091dc2fc85b8209d7cfd5d"
            "bd39d79a8dd7c6f981af064ce69e58a99fbd9ffd58a2d93d60972ec873f27feaedeed73f0a",
        },
    };

    for (i = 0; i < RTL_NUMBER_OF(expand_vector); i++) {
        binary_t prk;
        kdf.cmac_kdf_extract(prk, crypt_algorithm_t::aes128, base16_decode(expand_vector[i].salt), base16_decode(expand_vector[i].ikm));
        // cmac_kdf_extract(prk, crypt_algorithm_t::aes128, salt, base16_decode(expand_vector[i].ikm));

        binary_t okm;
        kdf.cmac_kdf_expand(okm, crypt_algorithm_t::aes128, expand_vector[i].dlen, base16_decode(expand_vector[i].prk), base16_decode(expand_vector[i].info));

        binary_t ckdf_okm;
        kdf.cmac_kdf(ckdf_okm, crypt_algorithm_t::aes128, expand_vector[i].dlen, base16_decode(expand_vector[i].ikm), base16_decode(expand_vector[i].salt),
                     base16_decode(expand_vector[i].info));

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("CKDF_Extract PRK", prk);
            _logger->hdump("CKDF_Expand OKM", okm);
            _logger->hdump("CKDF OKM", ckdf_okm);
        }

        _test_case.assert(okm == base16_decode(expand_vector[i].okm), __FUNCTION__, "CKDF-Expand %s", expand_vector[i].desc);
        _test_case.assert(ckdf_okm == base16_decode(expand_vector[i].okm), __FUNCTION__, "CKDF %s", expand_vector[i].desc);
    }
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-s", "test slow pbkdf2/scrypt", [&](OPTION& o, char* param) -> void { o.test_slow_kdf = true; }).optional();

    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        test_kdf_hkdf();

        // debugging problem (takes a long time), valgrind --tool=helgrind or --tool=drd ...
        if (option.test_slow_kdf) {
            test_kdf_pbkdf2_rfc6070();
            test_kdf_pbkdf2_rfc7914();
            test_kdf_scrypt_rfc7914();
        }
        test_kdf_argon_rfc9106();

        test_kdf_extract_expand_rfc5869();
        test_ckdf_rfc4615();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    _logger->consoleln("openssl 3 deprected bf, idea, seed");
    return _test_case.result();
}

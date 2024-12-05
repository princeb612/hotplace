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

// RFC 4615
// The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128
// (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)
void test_ckdf_rfc4615() {
    _test_case.begin("CMAC-based Extract-and-Expand Key Derivation Function (CKDF)");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;
    openssl_mac mac;

    // RFC 4615 AES-CMAC-PRF-128
    // study step.1 CKDF_Extract
    struct {
        const char* desc;
        const char* salt;  // key
        const char* ikm;   // message
        const char* prk;   // RFC 4493 AES-CMAC, RFC 4615 PRF output
    } extract_vector[] = {
        {
            "RFC 4615 4.  Test Vectors #1",
            "000102030405060708090a0b0c0d0e0fedcb",
            "000102030405060708090a0b0c0d0e0f10111213",
            "84a348a4a45d235babfffc0d2b4da09a",
        },
        {
            "RFC 4615 4.  Test Vectors #2",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "980ae87b5f4c9c5214f5b6a8455e4c2d",
        },
        {
            "RFC 4615 4.  Test Vectors #3",
            "00010203040506070809",
            "000102030405060708090a0b0c0d0e0f10111213",
            "290d9e112edb09ee141fcf64c0b72f3d",
        },
        {
            "RFC 4493 4.  Test Vectors Example 1",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "",
            "bb1d6929e95937287fa37d129b756746",
        },
        {
            "RFC 4493 4.  Test Vectors Example 2",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "070a16b46b4d4144f79bdd9dd04a287c",
        },
        {
            "RFC 4493 4.  Test Vectors Example 3",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411",
            "dfa66747 de9ae630 30ca3261 1497c827",
        },
        {
            "RFC 4493 4.  Test Vectors Example 4",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710",
            "51f0bebf 7e3b9d92 fc497417 79363cfe",
        },
        {
            // CMAC-based Extract-and-Expand Key Derivation Function (CKDF) draft-agl-ckdf-01
            "draft-agl-ckdf-01 Test Case (empty salt)",
            "",  // empty salt
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

        auto desc = extract_vector[i].desc;
        binary_t salt = base16_decode_rfc(extract_vector[i].salt);
        binary_t ikm = base16_decode_rfc(extract_vector[i].ikm);
        binary_t prk = base16_decode_rfc(extract_vector[i].prk);

        kdf.cmac_kdf_extract(output, crypt_algorithm_t::aes128, salt, ikm);

        if (option.verbose) {
            _logger->hdump("Salt", salt);
            _logger->hdump("IKM", ikm);
            _logger->hdump("PRK", prk);
            _logger->dump(output);
        }

        _test_case.assert(output == prk, __FUNCTION__, "%s - CKDF_Extract, AES-CMAC-PRF-128", desc);

        binary_t output2;
        mac.cmac("aes-128-cbc", salt, ikm, output2);
        if (option.verbose) {
            _logger->hdump("cmac", output2);
        }
        _test_case.assert(output == output2, __FUNCTION__, "%s - openssl_mac::cmac", desc);
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
        /**
         *  draft-agl-ckdf-01
         *
         *   PRK:  6f79b401 ea761a01 00b7ca60 c178b69d
         *   Info: (empty)
         *   L:    32
         *   OKM:  922da31d 7e1955f0 6a56464b 5feb7032 8f7e6f60 aaea5735
         *         c2772e33 17d0a288
         *
         *   PRK:  6f79b401 ea761a01 00b7ca60 c178b69d
         *   Info: 696e666f 20737472 696e67
         *   L:    256
         *   OKM:  6174e672 12e1234b 6e05bfd3 1043422c df1e34cd 29ee09f5
         *         bd5edb90 db39dcd4 c301e873 d91acbd5 333c8701 6dda05be
         *         3a8faade 2c3992c8 f3221f05 5efb3b51 76dbbe76 90cb4400
         *         f737298d 638b8026 d527c1e5 81f4e37d a0499c31 abfd8908
         *         207160de 343c126e cb460e38 8481fa9f 73391fe6 35a0e4b6
         *         cde3d385 78bcb8b5 5a60952b ac6f840f d87c397a c2477992
         *         ac6cbd64 3100e3ca d660373b 44e2fc0e 4867b15a cd9a070a
         *         3229ee40 76bf9851 7ccc656f 5bf1f8bb 41ce7e2d 48db670f
         *         1b2921ee 462d9cf1 987eb983 e5c2ce4e a9ceea10 c301dcca
         *         f16c4b57 67daa4bf 6ecc8161 77da31a5 9a9b1972 86259bd6
         *         598d2874 a4f605fb 877bee1b 5529873f
         */
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
        binary_t bin_prk;

        auto desc = expand_vector[i].desc;
        auto dlen = expand_vector[i].dlen;
        binary_t salt = base16_decode(expand_vector[i].salt);
        binary_t ikm = base16_decode(expand_vector[i].ikm);
        binary_t prk = base16_decode(expand_vector[i].prk);
        binary_t info = base16_decode(expand_vector[i].info);
        binary_t okm = base16_decode(expand_vector[i].okm);

        kdf.cmac_kdf_extract(bin_prk, crypt_algorithm_t::aes128, salt, ikm);

        binary_t bin_okm;
        kdf.cmac_kdf_expand(bin_okm, crypt_algorithm_t::aes128, dlen, prk, info);

        binary_t ckdf_okm;
        kdf.cmac_kdf(ckdf_okm, crypt_algorithm_t::aes128, dlen, ikm, salt, info);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("Salt", salt);
            _logger->hdump("IKM", ikm);
            _logger->hdump("PRK", prk);
            _logger->hdump("CKDF_Extract PRK", bin_prk);
            _logger->hdump("CKDF_Expand OKM", bin_okm);
            _logger->hdump("CKDF OKM", ckdf_okm);
        }

        _test_case.assert(bin_prk == prk, __FUNCTION__, "%s - CKDF-Extract", desc);
        _test_case.assert(bin_okm == okm, __FUNCTION__, "%s - CKDF-Expand", desc);
        _test_case.assert(ckdf_okm == okm, __FUNCTION__, "%s - CKDF", desc);
    }
}

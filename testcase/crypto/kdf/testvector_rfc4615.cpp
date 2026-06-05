/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_rfc4615.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

// RFC 4615
// The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128
// (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)
void test_rfc4615() {
    _test_case.begin("CMAC-based Extract-and-Expand Key Derivation Function (CKDF)");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;
    openssl_mac mac;

    basic_stream bs;

    auto lambda_yaml_rfc4615 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_salt = item["salt"].as<std::string>("");
                auto text_ikm = item["ikm"].as<std::string>("");
                auto text_prk = item["prk"].as<std::string>("");

                auto desc = item["item"].as<std::string>("");
                auto salt = base16_decode_rfc(text_salt);  // key
                auto ikm = base16_decode_rfc(text_ikm);    // message
                auto prk = base16_decode_rfc(text_prk);    // RFC 4493 AES-CMAC, RFC 4615 PRF output

                // RFC 4615 AES-CMAC-PRF-128
                // step.1 CKDF_Extract

                binary_t output;
                kdf.cmac_kdf_extract(output, crypt_algorithm_t::aes128, salt, ikm);

                if (option.verbose) {
                    _logger->hdump("Salt", salt);
                    _logger->hdump("IKM", ikm);
                    _logger->hdump("PRK", prk);
                    _logger->dump(output);
                }

                _test_case.assert(output == prk, __FUNCTION__, "%s - CKDF_Extract, AES-CMAC-PRF-128", desc.c_str());

                // step.2 CKDF_Expand
                // step.3 CKDF

                binary_t output2;
                mac.cmac("aes-128-cbc", salt, ikm, output2);
                if (option.verbose) {
                    _logger->hdump("cmac", output2);
                }
                _test_case.assert(output == output2, __FUNCTION__, "%s - openssl_mac::cmac", desc.c_str());
            }
        }
    };

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
    auto lambda_yaml_ckdf = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_salt = item["salt"].as<std::string>("");
                auto text_ikm = item["ikm"].as<std::string>("");
                auto text_prk = item["prk"].as<std::string>("");
                auto text_info = item["info"].as<std::string>("");
                auto text_okm = item["okm"].as<std::string>("");
                auto len = item["len"].as<int>(0);

                auto desc = item["item"].as<std::string>("");
                auto salt = base16_decode_rfc(text_salt);
                auto ikm = base16_decode_rfc(text_ikm);
                auto prk = base16_decode_rfc(text_prk);
                auto info = base16_decode_rfc(text_info);
                auto okm = base16_decode_rfc(text_okm);

                binary_t bin_prk;
                kdf.cmac_kdf_extract(bin_prk, crypt_algorithm_t::aes128, salt, ikm);

                binary_t bin_okm;
                kdf.cmac_kdf_expand(bin_okm, crypt_algorithm_t::aes128, len, prk, info);

                binary_t ckdf_okm;
                kdf.cmac_kdf(ckdf_okm, crypt_algorithm_t::aes128, len, ikm, salt, info);

                if (option.verbose) {
                    test_case_notimecheck notimecheck(_test_case);

                    _logger->hdump("Salt", salt);
                    _logger->hdump("IKM", ikm);
                    _logger->hdump("PRK", prk);
                    _logger->hdump("CKDF_Extract PRK", bin_prk);
                    _logger->hdump("CKDF_Expand OKM", bin_okm);
                    _logger->hdump("CKDF OKM", ckdf_okm);
                }

                _test_case.assert(bin_prk == prk, __FUNCTION__, "%s - CKDF-Extract", desc.c_str());
                _test_case.assert(bin_okm == okm, __FUNCTION__, "%s - CKDF-Expand", desc.c_str());
                _test_case.assert(ckdf_okm == okm, __FUNCTION__, "%s - CKDF", desc.c_str());
            }
        }
    };

    yaml_testcase test;
    test.add("RFC 4615", lambda_yaml_rfc4615).add("CKDF", lambda_yaml_ckdf).run("testvector_rfc4615.yml");
}

void testcase_testvector_rfc4615() { test_rfc4615(); }

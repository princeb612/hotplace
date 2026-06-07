/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_rfc5869.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_rfc5869() {
    _test_case.begin("RFC 5869 Appendix A.  Test Vectors");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    // RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

    basic_stream bs;

    auto lambda_yaml_rfc5869 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_item = item["item"].as<std::string>("");
                auto text_alg = item["alg"].as<std::string>("");
                auto text_ikm = item["ikm"].as<std::string>("");
                auto text_salt = item["salt"].as<std::string>("");
                auto text_info = item["info"].as<std::string>("");
                auto dlen = item["dlen"].as<int>(0);
                auto text_prk = item["prk"].as<std::string>("");
                auto text_okm = item["okm"].as<std::string>("");

                // 2.2 Step 1: Extract
                //  PRK = HMAC-Hash(salt, IKM)
                auto alg = typeof_alg(advisor->hintof_digest(text_alg));
                binary_t ikm = base16_decode_rfc(text_ikm);
                binary_t salt = base16_decode_rfc(text_salt);
                binary_t info = base16_decode_rfc(text_info);
                binary_t prk = base16_decode_rfc(text_prk);
                binary_t okm = base16_decode_rfc(text_okm);

                binary_t bin_prk;
                kdf.hmac_kdf_extract(bin_prk, alg, salt, ikm);
                _test_case.assert((bin_prk == prk), __FUNCTION__, "%s - KDF_Extract", text_item.c_str());

                // 2.3 Step 2: Expand
                //  HKDF-Expand(PRK, info, L) -> OKM
                binary_t bin_okm;
                kdf.hkdf_expand(bin_okm, alg, dlen, bin_prk, info);
                if (option.verbose) {
                    _logger->hdump("OKM", bin_okm);
                }
                _test_case.assert((bin_okm == okm), __FUNCTION__, "%s - KDF_Expand", text_item.c_str());

                binary_t derived;
                kdf.hmac_kdf(derived, alg, dlen, ikm, salt, info);
                if (option.verbose) {
                    _logger->hdump("HKDF", derived);
                }
                _test_case.assert((bin_okm == derived), __FUNCTION__, "%s - EVP_PKEY_derive", text_item.c_str());
            }
        }
    };

    yaml_testcase test;
    test.add("RFC 5869", lambda_yaml_rfc5869).run("testvector_rfc5869.yml");
}

void testcase_testvector_rfc5869() { test_rfc5869(); }

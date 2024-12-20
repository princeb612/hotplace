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

void test_crypto_sign() {
    _test_case.begin("crypto_sign");

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    crypto_key key;
    crypto_keychain keychain;
    // rfc8037_A_ed25519.jwk
    {
        const char* x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        const char* y = "";
        const char* d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        keychain.add_ec_b64u(&key, "Ed25519", x, y, d, keydesc("Ed25519"));
    }
    //
    {
        const char* x = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
        const char* y = "";
        const char* d = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
        keychain.add_ec_b16(&key, "Ed448", x, y, d, keydesc("Ed448"));
    }
    // rfc7520_priv.jwk
    {
        const char* x = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
        const char* y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1";
        const char* d = "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt";
        keychain.add_ec_b64u(&key, "P-521", x, y, d, keydesc("P-521"));
    }
    {
        const char* x = "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2";
        const char* y = "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP";
        const char* d = "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j";
        keychain.add_ec_b64u(&key, "P-384", x, y, d, keydesc("P-384"));
    }
    {
        const char* x = "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0";
        const char* y = "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw";
        const char* d = "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8";
        keychain.add_ec_b64u(&key, "P-256", x, y, d, keydesc("P-256"));
    }
    {
        const char* n =
            "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-"
            "QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_"
            "3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
        const char* e = "AQAB";
        const char* d =
            "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_"
            "qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-"
            "LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ";
        keychain.add_rsa_b64u(&key, NID_rsaEncryption, n, e, d, keydesc("RSA"));
        keychain.add_rsa_b64u(&key, NID_rsassaPss, n, e, d, keydesc("RSA_PSS"));
    }

    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    binary_t bin_sample = str2bin(sample);

    auto lambda_sign_kid = [&](const char* text, const char* kid, crypto_kty_t kty, crypt_sig_type_t scheme, hash_algorithm_t alg, bool expect) -> void {
        binary_t signature1;
        binary_t signature2;
        const EVP_PKEY* pkey = key.find(kid, kty);
        const char* algname = advisor->nameof_md(alg);

        crypto_sign_builder builder;
        auto sign = builder.set_scheme(scheme).set_digest(alg).build();
        if (sign) {
            ret = sign->sign(pkey, bin_sample, signature2);
            _logger->hdump(format("> %s", text), signature2);
            if (expect) {
                _test_case.test(ret, __FUNCTION__, "%s kid:%s alg:%s #sign", text, kid, algname);
            } else {
                _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "%s kid:%s alg:%s #sign-fail", text, kid, algname);
            }

            ret = sign->verify(pkey, bin_sample, signature2);
            if (expect) {
                _test_case.test(ret, __FUNCTION__, "%s kid:%s alg:%s #verify", text, kid, algname);
            } else {
                _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "%s kid:%s alg:%s #verify-fail", text, kid, algname);
            }

            sign->release();
        }
    };

    lambda_sign_kid("EdDSA", "Ed25519", kty_okp, crypt_sig_eddsa, hash_algorithm_t::hash_alg_unknown, true);
    lambda_sign_kid("EdDSA", "Ed448", kty_okp, crypt_sig_eddsa, hash_algorithm_t::hash_alg_unknown, true);
    lambda_sign_kid("ECDSA", "P-521", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("ECDSA", "P-521", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, false);
    lambda_sign_kid("ECDSA", "P-521", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, false);
    lambda_sign_kid("ECDSA", "P-384", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("ECDSA", "P-384", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "P-384", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, false);
    lambda_sign_kid("ECDSA", "P-256", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "P-256", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "P-256", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("RSA.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("RSA.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("RSA.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("PSS.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("PSS.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("PSS.RSA", "RSA", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("PSS.PSS", "RSA_PSS", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("PSS.PSS", "RSA_PSS", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("PSS.PSS", "RSA_PSS", kty_rsa, crypt_sig_rsassa_pss, hash_algorithm_t::sha2_512, true);
}

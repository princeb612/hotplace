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
        keychain.add_ec(&key, NID_secp112r1, keydesc("NID_secp112r1"));
        keychain.add_ec(&key, NID_secp112r2, keydesc("NID_secp112r2"));
        keychain.add_ec(&key, NID_secp128r1, keydesc("NID_secp128r1"));
        keychain.add_ec(&key, NID_secp128r2, keydesc("NID_secp128r2"));
        keychain.add_ec(&key, NID_secp160k1, keydesc("NID_secp160k1"));
        keychain.add_ec(&key, NID_secp160r1, keydesc("NID_secp160r1"));
        keychain.add_ec(&key, NID_secp160r2, keydesc("NID_secp160r2"));
        keychain.add_ec(&key, NID_secp192k1, keydesc("NID_secp192k1"));
        keychain.add_ec(&key, NID_X9_62_prime192v1, keydesc("NID_X9_62_prime192v1"));
        keychain.add_ec(&key, NID_secp224k1, keydesc("NID_secp224k1"));
        keychain.add_ec(&key, NID_secp224r1, keydesc("NID_secp224r1"));
        keychain.add_ec(&key, NID_secp256k1, keydesc("NID_secp256k1"));
        keychain.add_ec(&key, NID_X9_62_prime256v1, keydesc("NID_X9_62_prime256v1"));
        keychain.add_ec(&key, NID_secp384r1, keydesc("NID_secp384r1"));
        keychain.add_ec(&key, NID_secp521r1, keydesc("NID_secp521r1"));
        keychain.add_ec(&key, NID_sect113r1, keydesc("NID_sect113r1"));
        keychain.add_ec(&key, NID_sect113r2, keydesc("NID_sect113r2"));
        keychain.add_ec(&key, NID_sect131r1, keydesc("NID_sect131r1"));
        keychain.add_ec(&key, NID_sect131r2, keydesc("NID_sect131r2"));
        keychain.add_ec(&key, NID_sect163k1, keydesc("NID_sect163k1"));
        keychain.add_ec(&key, NID_sect163r1, keydesc("NID_sect163r1"));
        keychain.add_ec(&key, NID_sect163r2, keydesc("NID_sect163r2"));
        keychain.add_ec(&key, NID_sect193r1, keydesc("NID_sect193r1"));
        keychain.add_ec(&key, NID_sect193r2, keydesc("NID_sect193r2"));
        keychain.add_ec(&key, NID_sect233k1, keydesc("NID_sect233k1"));
        keychain.add_ec(&key, NID_sect233r1, keydesc("NID_sect233r1"));
        keychain.add_ec(&key, NID_sect239k1, keydesc("NID_sect239k1"));
        keychain.add_ec(&key, NID_sect283k1, keydesc("NID_sect283k1"));
        keychain.add_ec(&key, NID_sect283r1, keydesc("NID_sect283r1"));
        keychain.add_ec(&key, NID_sect409k1, keydesc("NID_sect409k1"));
        keychain.add_ec(&key, NID_sect409r1, keydesc("NID_sect409r1"));
        keychain.add_ec(&key, NID_sect571k1, keydesc("NID_sect571k1"));
        keychain.add_ec(&key, NID_sect571r1, keydesc("NID_sect571r1"));
        keychain.add_ec(&key, NID_X25519, keydesc("NID_X25519"));
        keychain.add_ec(&key, NID_X448, keydesc("NID_X448"));
        keychain.add_ec(&key, NID_ED25519, keydesc("NID_ED25519"));
        keychain.add_ec(&key, NID_ED448, keydesc("NID_ED448"));
        keychain.add_ec(&key, NID_brainpoolP160r1, keydesc("NID_brainpoolP160r1"));
        keychain.add_ec(&key, NID_brainpoolP160t1, keydesc("NID_brainpoolP160t1"));
        keychain.add_ec(&key, NID_brainpoolP192r1, keydesc("NID_brainpoolP192r1"));
        keychain.add_ec(&key, NID_brainpoolP192t1, keydesc("NID_brainpoolP192t1"));
        keychain.add_ec(&key, NID_brainpoolP224r1, keydesc("NID_brainpoolP224r1"));
        keychain.add_ec(&key, NID_brainpoolP224t1, keydesc("NID_brainpoolP224t1"));
        keychain.add_ec(&key, NID_brainpoolP256r1, keydesc("NID_brainpoolP256r1"));
        keychain.add_ec(&key, NID_brainpoolP256t1, keydesc("NID_brainpoolP256t1"));
        keychain.add_ec(&key, NID_brainpoolP320r1, keydesc("NID_brainpoolP320r1"));
        keychain.add_ec(&key, NID_brainpoolP320t1, keydesc("NID_brainpoolP320t1"));
        keychain.add_ec(&key, NID_brainpoolP384r1, keydesc("NID_brainpoolP384r1"));
        keychain.add_ec(&key, NID_brainpoolP384t1, keydesc("NID_brainpoolP384t1"));
        keychain.add_ec(&key, NID_brainpoolP512r1, keydesc("NID_brainpoolP512r1"));
        keychain.add_ec(&key, NID_brainpoolP512t1, keydesc("NID_brainpoolP512t1"));
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
        const OPTION option = _cmdline->value();
        // binary_t signature1;
        binary_t signature2;
        const EVP_PKEY* pkey = key.find(kid, kty);
        const char* algname = advisor->nameof_md(alg);

        crypto_sign_builder builder;
        auto sign = builder.set_scheme(scheme).set_digest(alg).build();
        if (sign) {
            if (option.dump_keys) {
                test_case_notimecheck notimecheck(_test_case);
                basic_stream bs;
                if (option.dump_keys) {
                    dump_key(pkey, &bs);
                    _logger->writeln("%s", bs.c_str());
                }
            }

            ret = sign->sign(pkey, bin_sample, signature2);
            _logger->hdump(format("> %s", text), signature2);
            if (expect) {
                _test_case.test(ret, __FUNCTION__, "%s kid:%s alg:%s #sign (len:%zi)", text, kid, algname, signature2.size());
            } else {
                _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "%s kid:%s alg:%s #sign-fail", text, kid, algname);
            }

            ret = sign->verify(pkey, bin_sample, signature2);
            if (expect) {
                _test_case.test(ret, __FUNCTION__, "%s kid:%s alg:%s #verify", text, kid, algname);
            } else {
                _test_case.ntest(ret, __FUNCTION__, "%s kid:%s alg:%s #verify-fail", text, kid, algname);
            }

            uint16 siglen = 0;
            if (kty_ec == kty) {
                switch (alg) {
                    case sha2_256:
                        siglen = 32 << 1;
                        break;
                    case sha2_384:
                        siglen = 48 << 1;
                        break;
                    case sha2_512:
                        siglen = 66 << 1;
                        break;
                }
                _test_case.assert(signature2.size() == siglen, __FUNCTION__, "%s kid:%s signature length %i <> %zi", text, kid, siglen, signature2.size());
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

    lambda_sign_kid("ECDSA", "NID_secp112r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp112r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp128r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp128r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp160k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp160r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp160r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp192k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_X9_62_prime192v1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp224k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp224r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp256k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_X9_62_prime256v1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_secp384r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_secp521r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("ECDSA", "NID_sect113r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect113r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect131r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect131r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect163k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect163r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect163r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect193r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect193r2", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect233k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect233r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect239k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_sect283k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_sect283r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_sect409k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("ECDSA", "NID_sect409r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    // lambda_sign_kid("ECDSA", "NID_sect571k1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    // lambda_sign_kid("ECDSA", "NID_sect571r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("EdDSA", "NID_ED25519", kty_okp, crypt_sig_eddsa, hash_algorithm_t::hash_alg_unknown, true);
    lambda_sign_kid("EdDSA", "NID_ED448", kty_okp, crypt_sig_eddsa, hash_algorithm_t::hash_alg_unknown, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP160r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP160t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP192r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP192t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP224r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP224t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP256r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP256t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_256, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP320r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP320t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP384r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP384t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_384, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP512r1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
    lambda_sign_kid("ECDSA", "NID_brainpoolP512t1", kty_ec, crypt_sig_ecdsa, hash_algorithm_t::sha2_512, true);
}

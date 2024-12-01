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

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    bool verbose;
    int log;
    int time;
    bool dump_keys;

    _OPTION() : verbose(false), log(0), time(0), dump_keys(false) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_hash_hmac_sign() {
    const OPTION& option = _cmdline->value();

    crypto_key key;
    crypto_keychain keychain;
    constexpr char key_source[] = "000102030405060708090a0b0c0d0e0f";
    // Rhapsody - Emerald Sword
    constexpr char in_source[] = "I crossed the valleys the dust of midlands / To search for the third key to open the gates";
    binary_t bin_key = base16_decode(key_source);
    binary_t bin_in = str2bin(in_source);

    keychain.add_oct_b16(&key, key_source, keydesc());
    binary_t result;

    openssl_hash hash;
    openssl_sign sign;

    if (option.verbose) {
        // source
        _logger->hdump("source", bin_in);
    }

    // openssl_hash hash
    hash_context_t* hash_context = nullptr;
    hash.open(&hash_context, hash_algorithm_t::sha2_256);
    hash.hash(hash_context, &bin_in[0], bin_in.size(), result);
    hash.close(hash_context);

    if (option.verbose) {
        _logger->hdump("hash", result);
    }

    // EVP_Digest (hash)
    unsigned int size = 0;
    result.resize(0);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);
    result.resize(size);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);

    if (option.verbose) {
        _logger->hdump("Digest", result);
    }

    // openssl_hash hmac
    hash_context_t* hmac_context = nullptr;
    hash.open(&hmac_context, hash_algorithm_t::sha2_256, &bin_key[0], bin_key.size());
    hash.hash(hmac_context, &bin_in[0], bin_in.size(), result);
    hash.close(hmac_context);

    if (option.verbose) {
        _logger->hdump("HMAC", result);
    }

    // openssl_sign
    sign.sign_digest(key.any(), hash_algorithm_t::sha2_256, bin_key, result);

    if (option.verbose) {
        _logger->hdump("Sign", result);
    }
}

void test_ecdsa(crypto_key* key, uint32 nid, hash_algorithm_t alg, const binary_t& input, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    switch (alg) {
        case sha2_512_224:
        case sha2_512_256:
            ret = errorcode_t::not_supported;
            break;
        default:
            break;
    }
#endif

    const hint_curve_t* hint = advisor->hintof_curve_nid(nid);
    const char* hashalg = advisor->nameof_md(alg);

    const EVP_PKEY* pkey = key->any();
    if (errorcode_t::success == ret) {
        /* check EC_GROUP_new_by_curve_name:unknown group */
        EC_KEY* ec = EC_KEY_new_by_curve_name(nid);

        if (ec) {
            EC_KEY_free(ec);
        } else {
            ret = errorcode_t::not_supported;
            ERR_clear_error();
        }
    }

    // using openssl_sign
    if (errorcode_t::success == ret) {
        openssl_sign sign;
        ret = sign.verify_ecdsa(pkey, alg, input, signature);
        const OPTION option = _cmdline->value();  // (*_cmdline).value () is ok

        if (option.dump_keys || option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            basic_stream bs;
            if (option.dump_keys) {
                dump_key(pkey, &bs);
                _logger->writeln("%s", bs.c_str());
            }
            if (option.verbose) {
                dump_memory(input, &bs);
                _logger->writeln("input\n%s", bs.c_str());
                dump_memory(signature, &bs);
                _logger->writeln("sig\n%s", bs.c_str());
            }
        }
        _test_case.test(ret, __FUNCTION__, "ECDSA.openssl_sign %s %s", hint ? hint->name : "", hashalg);
    }

    // using crypto_sign
    if (errorcode_t::success == ret) {
        crypto_sign_builder builder;
        crypto_sign* sign = builder.set_scheme(crypt_sig_ecdsa).set_digest(alg).build();
        if (sign) {
            ret = sign->verify(pkey, input, signature);
            _test_case.test(ret, __FUNCTION__, "ECDSA.crypto_sign  %s %s", hint ? hint->name : "", hashalg);
            sign->release();
        }
    }
}

void test_ecdsa_testvector(const test_vector_nist_cavp_ecdsa_t* vector, size_t sizeof_vector, int base16) {
    for (int i = 0; i < sizeof_vector; i++) {
        crypto_key key;
        crypto_keychain keychain;

        keychain.add_ec_b16(&key, vector[i].nid, vector[i].x, vector[i].y, vector[i].d, keydesc());
        binary_t signature;
        binary_t bin_r = base16_decode(vector[i].r);
        binary_t bin_s = base16_decode(vector[i].s);
        signature.insert(signature.end(), bin_r.begin(), bin_r.end());
        signature.insert(signature.end(), bin_s.begin(), bin_s.end());

        binary_t message;
        if (base16) {
            message = base16_decode(vector[i].msg);
        } else {
            message = str2bin(vector[i].msg);
        }
        test_ecdsa(&key, vector[i].nid, vector[i].alg, message, signature);
    }
}

void test_nist_cavp_ecdsa() {
    _test_case.begin("NIST CAVP ECDSA FIPS186-4");
    test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_4_signgen, sizeof_test_vector_nist_cavp_ecdsa_fips186_4_signgen, 1);
    _test_case.begin("NIST CAVP ECDSA FIPS186-4 TruncatedSHAs");
    test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas, sizeof_test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas, 1);
    _test_case.begin("NIST CAVP ECDSA FIPS186-2");
    test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_2_signgen, sizeof_test_vector_nist_cavp_ecdsa_fips186_2_signgen, 1);
}

void test_rfc6979_ecdsa() {
    _test_case.begin("RFC6979 ECDSA");
    test_ecdsa_testvector(test_vector_rfc6979, sizeof_test_vector_rfc6979, 0);
}

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

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = true; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
              << t_cmdarg_t<OPTION>("-k", "dump keys", [](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
    (*_cmdline).parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    _logger->consoleln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->consoleln("option.dump_keys %i", option.dump_keys ? 1 : 0);

    if (option.verbose) {
        set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    }

    __try2 {
        openssl_startup();

        test_hash_hmac_sign();

        test_nist_cavp_ecdsa();
        test_rfc6979_ecdsa();
        test_crypto_sign();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}

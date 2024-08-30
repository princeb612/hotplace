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
    bool dump_keys;

    _OPTION() : verbose(false), dump_keys(false) {
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
    binary_t bin_in = tobin(in_source);

    keychain.add_oct(&key, base16_decode(key_source));
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
    openssl_sign sign;

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

    if (errorcode_t::success == ret) {
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
    }

    _test_case.test(ret, __FUNCTION__, "ECDSA %s %s", hint ? hint->name : "", hashalg);
}

void test_ecdsa_testvector(const test_vector_nist_cavp_ecdsa_t* vector, size_t sizeof_vector, int base16) {
    for (int i = 0; i < sizeof_vector; i++) {
        crypto_key key;
        crypto_keychain keychain;

        keychain.add_ec(&key, vector[i].nid, base16_decode(vector[i].x), base16_decode(vector[i].y), base16_decode(vector[i].d));
        binary_t signature;
        binary_t bin_r = base16_decode(vector[i].r);
        binary_t bin_s = base16_decode(vector[i].s);
        signature.insert(signature.end(), bin_r.begin(), bin_r.end());
        signature.insert(signature.end(), bin_s.begin(), bin_s.end());

        binary_t message;
        if (base16) {
            message = base16_decode(vector[i].msg);
        } else {
            message = tobin(vector[i].msg);
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

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = true; }).optional()
              << t_cmdarg_t<OPTION>("-k", "dump keys", [&](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
    (*_cmdline).parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    _logger->consoleln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->consoleln("option.dump_keys %i", option.dump_keys ? 1 : 0);

    if (option.verbose) {
        set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    }

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        test_hash_hmac_sign();

        test_nist_cavp_ecdsa();
        test_rfc6979_ecdsa();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}

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

void do_test_ecdsa(crypto_key* key, uint32 nid, hash_algorithm_t alg, const binary_t& input, const binary_t& signature) {
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
                _logger->hdump("input", input);
                _logger->hdump("signature", signature);
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

void do_test_ecdsa_testvector(const test_vector_nist_cavp_ecdsa_t* vector, size_t sizeof_vector, int base16) {
    for (int i = 0; i < sizeof_vector; i++) {
        crypto_key key;
        crypto_keychain keychain;

        keychain.add_ec_b16(&key, vector[i].nid, vector[i].x, vector[i].y, vector[i].d, keydesc());
        binary_t signature;
        binary_t bin_r = std::move(base16_decode(vector[i].r));
        binary_t bin_s = std::move(base16_decode(vector[i].s));
        signature.insert(signature.end(), bin_r.begin(), bin_r.end());
        signature.insert(signature.end(), bin_s.begin(), bin_s.end());

        binary_t message;
        if (base16) {
            message = std::move(base16_decode(vector[i].msg));
        } else {
            message = std::move(str2bin(vector[i].msg));
        }
        do_test_ecdsa(&key, vector[i].nid, vector[i].alg, message, signature);
    }
}

void test_nist_cavp_ecdsa() {
    _test_case.begin("NIST CAVP ECDSA FIPS186-4");
    do_test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_4_signgen, sizeof_test_vector_nist_cavp_ecdsa_fips186_4_signgen, 1);
    _test_case.begin("NIST CAVP ECDSA FIPS186-4 TruncatedSHAs");
    do_test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas, sizeof_test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas, 1);
    _test_case.begin("NIST CAVP ECDSA FIPS186-2");
    do_test_ecdsa_testvector(test_vector_nist_cavp_ecdsa_fips186_2_signgen, sizeof_test_vector_nist_cavp_ecdsa_fips186_2_signgen, 1);
}

void test_rfc6979_ecdsa() {
    _test_case.begin("RFC6979 ECDSA");
    do_test_ecdsa_testvector(test_vector_rfc6979, sizeof_test_vector_rfc6979, 0);
}

void check_ecdsa_size() {
    _test_case.begin("ECDSA signature size");
    crypto_key key;
    crypto_keychain keychain;

#define ADD_KEY(x) keychain.add_ec(&key, x, keydesc(#x))
    ADD_KEY(NID_secp112r1);
    ADD_KEY(NID_secp112r2);
    ADD_KEY(NID_secp128r1);
    ADD_KEY(NID_secp128r2);
    ADD_KEY(NID_secp160k1);
    ADD_KEY(NID_secp160r1);
    ADD_KEY(NID_secp160r2);
    ADD_KEY(NID_secp192k1);
    ADD_KEY(NID_X9_62_prime192v1);
    ADD_KEY(NID_secp224k1);
    ADD_KEY(NID_secp224r1);
    ADD_KEY(NID_secp256k1);
    ADD_KEY(NID_X9_62_prime256v1);
    ADD_KEY(NID_secp384r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_sect113r2);
    ADD_KEY(NID_sect131r1);
    ADD_KEY(NID_sect131r2);
    ADD_KEY(NID_sect163k1);
    ADD_KEY(NID_sect163r1);
    ADD_KEY(NID_sect163r2);
    ADD_KEY(NID_sect193r1);
    ADD_KEY(NID_sect193r2);
    ADD_KEY(NID_sect233k1);
    ADD_KEY(NID_sect233r1);
    ADD_KEY(NID_sect239k1);
    ADD_KEY(NID_sect283k1);
    ADD_KEY(NID_sect283r1);
    ADD_KEY(NID_sect409k1);
    ADD_KEY(NID_sect409r1);
    ADD_KEY(NID_sect571k1);
    ADD_KEY(NID_sect571r1);
    ADD_KEY(NID_brainpoolP160r1);
    ADD_KEY(NID_brainpoolP160t1);
    ADD_KEY(NID_brainpoolP192r1);
    ADD_KEY(NID_brainpoolP192t1);
    ADD_KEY(NID_brainpoolP224r1);
    ADD_KEY(NID_brainpoolP224t1);
    ADD_KEY(NID_brainpoolP256r1);
    ADD_KEY(NID_brainpoolP256t1);
    ADD_KEY(NID_brainpoolP320r1);
    ADD_KEY(NID_brainpoolP320t1);
    ADD_KEY(NID_brainpoolP384r1);
    ADD_KEY(NID_brainpoolP384t1);
    ADD_KEY(NID_brainpoolP512r1);
    ADD_KEY(NID_brainpoolP512t1);

    hash_algorithm_t algs[] = {sha1, sha2_224, sha2_256, sha2_384, sha2_512, sha3_224, sha3_256, sha3_384, sha3_512};
    const char* source = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(source);

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypto_sign_builder builder;
    binary_t sig;
    binary_t zero;

    auto lambda = [&](crypto_key_object* keyobj, void*) -> void {
        for (auto alg : algs) {
            auto pkey = keyobj->get_pkey();

            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            auto hint = advisor->hintof_curve_nid(nid);
            bool test = support(hint, alg);
            if (false == test) {
                continue;
            }

            crypto_sign* sign = builder.set_scheme(crypt_sig_ecdsa).set_digest(alg).build();
            if (sign) {
                ret = sign->sign(pkey, (byte_t*)source, len, sig);
                const char* algname = advisor->nameof_md(alg);
                auto kid = keyobj->get_desc().get_kid_cstr();
                const std::string& desc = format("%-20s %-7s", kid, algname);

                _logger->hdump(desc, sig);

                if (success == ret) {
                    zero.resize(sig.size());
                    if (sig == zero) {
                        ret = errorcode_t::expect_failure;
                    }
                } else {
                    ret = expect_failure;
                }

                _test_case.test(ret, __FUNCTION__, "%s %-3zi", desc.c_str(), sig.size());
                sign->release();
            }
        }
    };
    key.for_each(lambda, nullptr);
}

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

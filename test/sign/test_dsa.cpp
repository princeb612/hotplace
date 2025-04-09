/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <map>

#include "sample.hpp"

void test_dsa() {
    _test_case.begin("NIST CAVP DSA FIPS186-3");
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    crypto_advisor *advisor = crypto_advisor::get_instance();
    std::map<std::string, const test_vector_nist_cavp_dsa_param_t *> param_map;

    for (auto i = 0; i < sizeof_test_vector_nist_cavp_dsa_param; i++) {
        auto item = test_vector_nist_cavp_dsa_param + i;
        param_map.insert({item->param, item});
    }

    for (auto i = 0; i < sizeof_test_vector_nist_cavp_dsa_fips186_3_signgen; i++) {
        auto item = test_vector_nist_cavp_dsa_fips186_3_signgen + i;
        crypto_key key;
        crypto_keychain keychain;

        const std::string &nameof_param = item->param;
        hash_algorithm_t hashalg = item->hashalg;
        binary_t msg = std::move(base16_decode(item->msg));
        binary_t bin_r = std::move(base16_decode(item->r));
        binary_t bin_s = std::move(base16_decode(item->s));

        auto param = param_map[nameof_param];
        keychain.add_dsa_b16(&key, nid_dsa, item->y, item->x, param->p, param->q, param->g, keydesc("DSA"));

        auto pkey = key.find("DSA");

        openssl_sign sign;
        ret = sign.verify_dsa(pkey, hashalg, msg, bin_r, bin_s);

        _logger->writeln("hash %s", advisor->nameof_md(hashalg));
        _logger->writeln("msg %s", item->msg);
        _logger->writeln("r %s", item->r);
        _logger->writeln("s %s", item->s);

        basic_stream bs;
        bs.printf(R"("%s" %s...)", nameof_param.c_str(), std::string(item->msg, 8).c_str());

        _test_case.test(ret, __FUNCTION__, "verify %s", bs.c_str());

        ret = sign.sign_dsa(pkey, hashalg, msg, bin_r, bin_s);
        _logger->hdump("signature #1 r", bin_r);
        _logger->hdump("signature #2 s", bin_s);
        _test_case.test(ret, __FUNCTION__, "sign %s", bs.c_str());
        ret = sign.verify_dsa(pkey, hashalg, msg, bin_r, bin_s);
        _test_case.test(ret, __FUNCTION__, "verify %s", bs.c_str());
    }
}

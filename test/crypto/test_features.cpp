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

void test_features() {
    _test_case.begin("features openssl version %08x", OpenSSL_version_num());
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto query_cipher = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_cipher);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature cipher "%s" [%08x])", feature, spec);
    };
    auto query_md = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_md);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature md "%s" [%08x])", feature, spec);
    };
    auto query_jwa = [&](const hint_jose_encryption_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->alg_name, advisor_feature_jwa);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWA "%s" [%08x])", item->alg_name, advisor_feature_jwa);
    };
    auto query_jwe = [&](const hint_jose_encryption_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->alg_name, advisor_feature_jwe);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWE "%s" [%08x])", item->alg_name, advisor_feature_jwe);
    };
    auto query_jws = [&](const hint_signature_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->jws_name, advisor_feature_jws);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWS "%s" [%08x])", item->jws_name, advisor_feature_jws);
    };
    auto query_cose = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_cose);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature COSE "%s" [%08x])", feature, spec);
    };
    auto query_curve = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_curve);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature Elliptic Curve "%s" [%08x])", feature, spec);
    };

    advisor->cipher_for_each(query_cipher, nullptr);
    advisor->md_for_each(query_md, nullptr);
    advisor->jose_for_each_algorithm(query_jwa, nullptr);
    advisor->jose_for_each_encryption(query_jwe, nullptr);
    advisor->jose_for_each_signature(query_jws, nullptr);
    advisor->cose_for_each(query_cose, nullptr);
    advisor->curve_for_each(query_curve, nullptr);
}

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

    advisor->for_each_cipher(query_cipher, nullptr);
    advisor->for_each_md(query_md, nullptr);
    advisor->for_each_jwa(query_jwa, nullptr);
    advisor->for_each_jwe(query_jwe, nullptr);
    advisor->for_each_jws(query_jws, nullptr);
    advisor->for_each_cose(query_cose, nullptr);
    advisor->for_each_curve(query_curve, nullptr);
}

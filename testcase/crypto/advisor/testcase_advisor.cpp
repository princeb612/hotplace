/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

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

void test_hint_curves() {
    _test_case.begin("curves");

    crypto_advisor* advisor = crypto_advisor::get_instance();

    _logger->writeln("kty OSSL-NID TLS-group curve");

    auto lambda = [&](const hint_curve_t* hint, void*) -> void {
        _logger->writeln([&](basic_stream& bs) -> void {
            bs.printf("%-3s     %4u    0x%04x ", advisor->nameof_kty(hint->kty), hint->nid, hint->tlsgroup);
            if (hint->name_nist) {
                bs << hint->name_nist << " ";
            }
            if (hint->name_x962) {
                bs << hint->name_x962 << " ";
            }
            if (hint->name_sec) {
                bs << hint->name_sec << " ";
            }
            if (hint->name_wtls) {
                bs << hint->name_wtls << " ";
            }
        });
    };
    advisor->for_each_curve_hint(lambda, nullptr);

    // EC  OSSL-NID  415 TLS-Group 0x0017 P-256 prime256v1 secp256r1
    // OKP OSSL-NID 1035 TLS-Group 0x001e X448
    auto hint_p256 = advisor->hintof_curve_name("P-256");
    auto hint_prime256v1 = advisor->hintof_curve_name("prime256v1");
    auto hint_secp256r1 = advisor->hintof_curve_name("secp256r1");
    _test_case.assert(415 == hint_p256->nid, __FUNCTION__, "P-256");
    _test_case.assert(415 == hint_prime256v1->nid, __FUNCTION__, "prime256v1");
    _test_case.assert(415 == hint_secp256r1->nid, __FUNCTION__, "secp256r1");
}

void test_resources() {
    // after modification, check sanities
    _test_case.begin("validate resources");

    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto lambda = [&](const hint_cipher_t* hint) -> void {
        auto test = ((hint->scheme) & 0x0000ffff) == (CRYPTO_SCHEME16(hint->algorithm, hint->mode));
        _test_case.assert(test, __FUNCTION__, "%s test scheme and {algorithm, mode}", hint->fetchname);

        auto hint_crosscheck = advisor->hintof_cipher(hint->fetchname);
        auto test_crosscheck = ((hint->scheme) & 0x0000ffff) == (CRYPTO_SCHEME16(hint_crosscheck->algorithm, hint_crosscheck->mode));
        _test_case.assert(test_crosscheck, __FUNCTION__, "%s test fetchname and {algorithm, mode}", hint->fetchname);
    };
    advisor->for_each_cipher(lambda);
}

void testcase_advisor() {
    test_features();
    test_hint_curves();
    test_resources();
}

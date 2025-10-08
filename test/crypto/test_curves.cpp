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

void test_curves() {
    _test_case.begin("curves");

    crypto_advisor* advisor = crypto_advisor::get_instance();

    _logger->writeln("kty OSSL-NID TLS-group curve");

    auto lambda = [&](const hint_curve_t* hint, void*) -> void {
        basic_stream bs;
        bs.printf("%-3s     %4u    0x%04x ", advisor->nameof_kty(hint->kty), hint->nid, hint->tlsgroup);
        if (hint->name) {
            bs << hint->name << " ";
        }
        if (hint->aka1) {
            bs << hint->aka1 << " ";
        }
        if (hint->aka2) {
            bs << hint->aka2 << " ";
        }
        if (hint->aka3) {
            bs << hint->aka3 << " ";
        }
        _logger->writeln(bs);
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

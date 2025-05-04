/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_validate_resource() {
    _test_case.begin("validate resources");

    struct keylen_table_t {
        cose_alg_t alg;
        uint16 keylen;
    } table[] = {
        {cose_aes128kw, 128 >> 3},
        {cose_aes128gcm, 128 >> 3},
        {cose_aesmac_128_64, 128 >> 3},
        {cose_aesmac_128_128, 128 >> 3},
        {cose_aesccm_16_64_128, 128 >> 3},
        {cose_aesccm_64_64_128, 128 >> 3},
        {cose_aesccm_16_128_128, 128 >> 3},
        {cose_aesccm_64_128_128, 128 >> 3},
        {cose_hkdf_sha256, 128 >> 3},
        {cose_hkdf_aes128, 128 >> 3},
        {cose_ecdhes_hkdf_256, 128 >> 3},
        {cose_ecdhss_hkdf_256, 128 >> 3},
        {cose_hs256_64, 128 >> 3},
        {cose_aes192kw, 192 >> 3},
        {cose_aes192gcm, 192 >> 3},
        {cose_aes256kw, 256 >> 3},
        {cose_aes256gcm, 256 >> 3},
        {cose_aesmac_256_64, 256 >> 3},
        {cose_aesmac_256_128, 256 >> 3},
        {cose_aesccm_16_64_256, 256 >> 3},
        {cose_aesccm_64_64_256, 256 >> 3},
        {cose_aesccm_16_128_256, 256 >> 3},
        {cose_aesccm_64_128_256, 256 >> 3},
        {cose_hkdf_sha512, 256 >> 3},
        {cose_hkdf_aes256, 256 >> 3},
        {cose_ecdhes_hkdf_512, 256 >> 3},
        {cose_ecdhss_hkdf_512, 256 >> 3},
        {cose_hs256, 256 >> 3},
        {cose_hs384, 384 >> 3},
        {cose_hs512, 512 >> 3},
    };
    crypto_advisor* advisor = crypto_advisor::get_instance();
    for (auto item : table) {
        auto hint = advisor->hintof_cose_algorithm(item.alg);
        bool test = (hint->enc.ksize == item.keylen);
        _test_case.assert(test, __FUNCTION__, "%s expect %i enc.ksize %i", hint->name, item.keylen, hint->enc.ksize);
    }
}

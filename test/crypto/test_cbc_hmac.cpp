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

void test_cbc_hmac(test_vector_cbchmac_tls_t* testvector, size_t size) {
    return_t ret = errorcode_t::success;
    crypto_cbc_hmac cbchmac;

    for (auto i = 0; i < size; i++) {
        const test_vector_cbchmac_tls_t* item = testvector + i;

        binary_t key = std::move(base16_decode(item->key));
        binary_t iv = std::move(base16_decode(item->iv));
        binary_t mackey = std::move(base16_decode(item->mackey));
        binary_t aad = std::move(base16_decode(item->aad));
        binary_t plaintext = std::move(base16_decode_rfc(item->plaintext));
        binary_t cbcmaced = std::move(base16_decode_rfc(item->cbcmaced));
        basic_stream desc;

        if (tls_mac_then_encrypt == item->flag) {
            desc = "mac_then_encrypt";
        } else if (tls_encrypt_then_mac == item->flag) {
            desc = "encrypt_then_mac";
        }
        desc.printf(R"(" %s")", item->desc);

        cbchmac.set_enc(aes128).set_mac(item->hashalg).set_flag(item->flag);

        _logger->writeln("> enckey %s", base16_encode(key).c_str());
        _logger->writeln("> iv     %s", base16_encode(iv).c_str());
        _logger->writeln("> mackey %s", base16_encode(mackey).c_str());
        _logger->writeln("> aad    %s", base16_encode(aad).c_str());

        binary_t pt;
        ret = cbchmac.decrypt(key, mackey, iv, aad, cbcmaced, pt);
        _test_case.test(ret, __FUNCTION__, "%s #decryption", desc.c_str());
        _logger->hdump("> cbcmaced", cbcmaced, 16, 2);
        _logger->writeln("  %s", base16_encode(cbcmaced).c_str());
        _logger->hdump("> plaintext", pt, 16, 2);
        _logger->writeln("  %s", base16_encode(pt).c_str());
        _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());

        binary_t ct;
        ret = cbchmac.encrypt(key, mackey, iv, aad, plaintext, ct);
        _test_case.test(ret, __FUNCTION__, "%s #encryption", desc.c_str());
        _logger->hdump("> plaintext", plaintext, 16, 2);
        _logger->writeln("  %s", base16_encode(plaintext).c_str());
        _logger->hdump("> cbcmaced", ct, 16, 2);
        _logger->writeln("  %s", base16_encode(ct).c_str());
        ret = cbchmac.decrypt(key, mackey, iv, aad, ct, pt);
        _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());
    }
}

void test_cbc_hmac_tls_mte() {
    _test_case.begin("mac_then_encrypt");

    test_cbc_hmac(test_vector_tls_mte, sizeof_test_vector_tls_mte);
}

void test_cbc_hmac_tls_etm() {
    _test_case.begin("encrypt_then_mac");

    test_cbc_hmac(test_vector_tls_etm, sizeof_test_vector_tls_etm);
}

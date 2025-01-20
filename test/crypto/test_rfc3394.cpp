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

void do_test_keywrap_rfc3394_testvector(const test_vector_rfc3394_t* vector) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    _test_case.reset_time();

    crypt_algorithm_t alg = vector->alg;
    const char* algname = vector->algname;
    const binary_t& kek = base16_decode(vector->kek);
    const binary_t& key = base16_decode(vector->key);
    const binary_t& expect = base16_decode(vector->expect);
    const char* msg = vector->message;

    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    binary_t iv;
    binary_fill(iv, 8, 0xa6);
    binary_t out_kw, out_kuw;

    ret = crypt.open(&handle, alg, crypt_mode_t::wrap, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, &key[0], key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            const char* nameof_alg = advisor->nameof_cipher(alg, crypt_mode_t::wrap);
            _logger->writeln("alg %s", nameof_alg);

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, &out_kw[0], out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == expect, __FUNCTION__, msg ? msg : "");

    ret = crypt.open(&handle, algname, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, &key[0], key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            const char* nameof_alg = advisor->nameof_cipher(alg, crypt_mode_t::wrap);
            _logger->writeln("alg %s", nameof_alg);

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, &out_kw[0], out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == expect, __FUNCTION__, msg ? msg : "");
}

void test_keywrap_rfc3394() {
    _test_case.begin("keywrap");

    for (int i = 0; i < sizeof_test_vector_rfc3394; i++) {
        do_test_keywrap_rfc3394_testvector(test_vector_rfc3394 + i);
    }
}

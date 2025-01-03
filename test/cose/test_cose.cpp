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

void dump_diagnostic(const binary_t& input) {
    const OPTION& option = _cmdline->value();
    if (option.dump_diagnostic) {
        basic_stream diagnostic;
        cbor_reader_context_t* handle = nullptr;
        cbor_reader reader;
        auto ret = reader.open(&handle);
        if (errorcode_t::success == ret) {
            ret = reader.parse(handle, input);
            reader.publish(handle, &diagnostic);
            reader.close(handle);
        }
        _logger->colorln(diagnostic);
    }
}

void test_sign(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("sign");

    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.sign(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "sign %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "verifysign %s", text);
}

void test_encrypt(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("encrypt");

    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.encrypt(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "encrypt %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "decrypt %s", text);
}

void test_mac(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("mac");

    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.mac(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "mac %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "verifymac %s", text);
}

void test_keygen(crypto_key* key) {
    crypto_keychain keychain;
    keychain.add_oct(key, 32, keydesc("kid_symm", crypto_use_t::use_any));
    keychain.add_rsa(key, nid_rsa, 2048, keydesc("kid_rsa", crypto_use_t::use_any));
    keychain.add_ec(key, ec_curve_t::ec_p256, keydesc("kid_ec256", crypto_use_t::use_any));
    keychain.add_ec(key, ec_curve_t::ec_p256k, keydesc("kid_ec256k", crypto_use_t::use_any));
    keychain.add_ec(key, ec_curve_t::ec_p384, keydesc("kid_ec384", crypto_use_t::use_any));
    keychain.add_ec(key, ec_curve_t::ec_p521, keydesc("kid_ec521", crypto_use_t::use_any));
    keychain.add_ec(key, ec_curve_t::ec_x25519, keydesc("kid_x25519", crypto_use_t::use_enc));
    keychain.add_ec(key, ec_curve_t::ec_ed25519, keydesc("kid_ed25519", crypto_use_t::use_sig));
    key->for_each(dump_crypto_key, nullptr);
    _test_case.assert(key->size() > 0, __FUNCTION__, "key generation");
}

const cose_alg_t enc_algs[] = {
    cose_aes128gcm,        cose_aes192gcm,         cose_aes256gcm,         cose_aesccm_16_64_128,  cose_aesccm_16_64_256,  cose_aesccm_64_64_128,
    cose_aesccm_64_64_256, cose_aesccm_16_128_128, cose_aesccm_16_128_256, cose_aesccm_64_128_128, cose_aesccm_64_128_256,
};
const cose_alg_t sign_algs[] = {
    cose_es256, cose_es384, cose_es512, cose_eddsa, cose_ps256, cose_ps384, cose_ps512, cose_es256k, cose_rs256, cose_rs384, cose_rs512, cose_rs1,
};
const cose_alg_t mac_algs[] = {
    cose_hs256_64, cose_hs256, cose_hs384, cose_hs512, cose_aesmac_128_64, cose_aesmac_256_64, cose_aesmac_128_128, cose_aesmac_256_128,
};
const cose_alg_t key_algs[] = {
    cose_aes128kw,      cose_aes192kw,        cose_aes256kw,        cose_direct,          cose_hkdf_sha256,     cose_hkdf_sha512,   cose_hkdf_aes128,
    cose_hkdf_aes256,   cose_ecdhes_hkdf_256, cose_ecdhes_hkdf_512, cose_ecdhss_hkdf_256, cose_ecdhss_hkdf_512, cose_ecdhes_a128kw, cose_ecdhes_a192kw,
    cose_ecdhes_a256kw, cose_ecdhss_a128kw,   cose_ecdhss_a192kw,   cose_ecdhss_a256kw,   cose_rsaoaep1,        cose_rsaoaep256,    cose_rsaoaep512,
};

void test_selfgen(crypto_key* key) {
    _test_case.begin("key generation");

    crypto_advisor* advisor = crypto_advisor::get_instance();
    binary_t input = str2bin("hello world");
    std::list<cose_alg_t> algs;
    size_t i = 0;
    size_t j = 0;
    for (i = 0; i < RTL_NUMBER_OF(sign_algs); i++) {
        algs.clear();
        cose_alg_t alg = sign_algs[i];
        algs.push_back(alg);
        std::string text = format("%i(%s)", alg, advisor->nameof_cose_algorithm(alg));
        test_sign(key, algs, input, text.c_str());
    }

    for (i = 0; i < RTL_NUMBER_OF(enc_algs); i++) {
        cose_alg_t alg = enc_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            algs.clear();
            cose_alg_t keyalg = key_algs[j];
            algs.push_back(alg);
            algs.push_back(keyalg);

            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_encrypt(key, algs, input, text.c_str());
        }
    }

    for (i = 0; i < RTL_NUMBER_OF(mac_algs); i++) {
        cose_alg_t alg = mac_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            algs.clear();
            cose_alg_t keyalg = key_algs[j];
            algs.push_back(alg);
            algs.push_back(keyalg);

            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_mac(key, algs, input, text.c_str());
        }
    }
}

void test_cose_encrypt(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    const OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);
    if (cose_alg_t::cose_unknown != keyalg) {
        cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
        recipient.get_protected().add(cose_key_t::cose_alg, keyalg);

        // fill others and compose
        ret = cose.encrypt(handle, key, input, cbor);
    }

    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose_sign(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    const OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);

    // fill others and compose
    ret = cose.encrypt(handle, key, input, cbor);

    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose_mac(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    const OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);
    if (cose_alg_t::cose_unknown != keyalg) {
        cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
        recipient.get_protected().add(cose_key_t::cose_alg, keyalg);

        // fill others and compose
        ret = cose.encrypt(handle, key, input, cbor);
    }

    cose.close(handle);

    dump_diagnostic(cbor);
    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose(crypto_key* key) {
    _test_case.begin("it's fun");

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption cose;
    binary_t input = str2bin("hello world");
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < RTL_NUMBER_OF(enc_algs); i++) {
        cose_alg_t alg = enc_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            cose_alg_t keyalg = key_algs[j];
            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_cose_encrypt(key, alg, keyalg, input, text.c_str());
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(sign_algs); i++) {
        cose_alg_t alg = sign_algs[i];

        std::string text = format("%i(%s)", alg, advisor->nameof_cose_algorithm(alg));
        test_cose_sign(key, alg, cose_alg_t::cose_unknown, input, text.c_str());
    }
    for (i = 0; i < RTL_NUMBER_OF(mac_algs); i++) {
        cose_alg_t alg = mac_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            cose_alg_t keyalg = key_algs[j];
            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_cose_mac(key, alg, keyalg, input, text.c_str());
        }
    }
}

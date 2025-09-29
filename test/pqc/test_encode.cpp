/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/pqc.hpp>

#include "sample.hpp"

// install oqsprovider.dll into ossl-modules

void do_encode(oqs_context* context, const std::string& alg, oqs_key_encoding_t encoding, const char* passphrase = nullptr) {
    return_t ret = errorcode_t::success;
    pqc_oqs pqc;
    EVP_PKEY* pkey = nullptr;
    binary_t capsulekey;
    binary_t sharedsecret;
    binary_t pubkey;

    _test_case.begin("encoding [%s]", pqc.nameof_encoding(encoding).c_str());

    pqc.keygen(context, alg.c_str(), &pkey);
    _test_case.assert(nullptr != pkey, __FUNCTION__, "keygen %s", alg.c_str());

    ret = pqc.encode_key(context, pkey, pubkey, encoding, passphrase);
    if (OQS_KEY_ENCODING_PEM & encoding) {
        _logger->writeln("%.*s", (int)pubkey.size(), (char*)&pubkey[0]);
    } else {
        _logger->writeln("key %s", base16_encode(pubkey).c_str());
    }
    _test_case.test(ret, __FUNCTION__, "encode %s", alg.c_str());

    EVP_PKEY* pkey_decoded = nullptr;
    ret = pqc.decode_key(context, &pkey_decoded, pubkey, encoding, passphrase);
    _test_case.test(ret, __FUNCTION__, "decode %s", alg.c_str());

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey_decoded);
}

void test_encode() {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        oqs_context* context = nullptr;
        pqc_oqs pqc;
        const char* passphrase = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";

        ret = pqc.open(&context);
        if (errorcode_t::success == ret) {
            pqc.for_each(context, OSSL_OP_KEM, [&](const std::string& alg) -> void {
                _logger->writeln("algorithm : %s", alg.c_str());
                do_encode(context, alg, oqs_key_encoding_priv_pem);
                do_encode(context, alg, oqs_key_encoding_encrypted_priv_pem, passphrase);
                do_encode(context, alg, oqs_key_encoding_pub_pem);
                do_encode(context, alg, oqs_key_encoding_priv_der);
                do_encode(context, alg, oqs_key_encoding_encrypted_priv_der, passphrase);
                do_encode(context, alg, oqs_key_encoding_pub_der);
            });
            pqc.for_each(context, OSSL_OP_SIGNATURE, [&](const std::string& alg) -> void {
                _logger->writeln("algorithm : %s", alg.c_str());
                do_encode(context, alg, oqs_key_encoding_priv_pem);
                do_encode(context, alg, oqs_key_encoding_encrypted_priv_pem, passphrase);
                do_encode(context, alg, oqs_key_encoding_pub_pem);
                do_encode(context, alg, oqs_key_encoding_priv_der);
                do_encode(context, alg, oqs_key_encoding_encrypted_priv_der, passphrase);
                do_encode(context, alg, oqs_key_encoding_pub_der);
            });

            pqc.close(context);
        }
    }
    __finally2 {}
}

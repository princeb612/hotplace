/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          -dump : dump all keys
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

return_t test_rfc7520_signature(crypto_key* key, const char* filename, const char* testcase_name) {
    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    file_stream fs;
    return_t ret = errorcode_t::success;
    bool result = false;

    ret = fs.open(filename);
    if (errorcode_t::success == ret) {
        fs.begin_mmap();

        byte_t* data = fs.data();
        size_t datasize = fs.size();
        if (data) {
            ret = jws.verify(key, std::string((char*)data, datasize), result);
        }
        fs.end_mmap();
        fs.close();
    }
    _test_case.test(ret, __FUNCTION__, testcase_name);
    return ret;
}

return_t test_rfc7520_jwe(crypto_key* key, const char* filename, const char* testcase_name) {
    _logger->writeln("%s", testcase_name);

    json_object_signing_encryption jose;
    jose_context_t* handle = nullptr;
    file_stream fs;
    basic_stream bs;
    return_t ret = errorcode_t::success;
    bool result = false;
    binary_t output;

    ret = fs.open(filename);
    if (errorcode_t::success == ret) {
        fs.begin_mmap();

        byte_t* data = fs.data();
        size_t datasize = fs.size();
        if (data) {
            jose.open(&handle, key);
            ret = jose.decrypt(handle, std::string((char*)data, datasize), output, result);
            if (errorcode_t::success == ret) {
                dump2("plain", data, datasize);
                dump2("decrypted", output);
            }
            jose.close(handle);
        }
        fs.end_mmap();
        fs.close();
    }
    _test_case.test(ret, __FUNCTION__, testcase_name);
    return ret;
}

void test_rfc7520() {
    print_text("RFC 7520");
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7520_priv.jwk");
    key.for_each(dump_crypto_key, nullptr);

    // 4.1 "RS256"
    test_rfc7520_signature(&key, "rfc7520_figure13.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 13)");
    test_rfc7520_signature(&key, "rfc7520_figure14.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 14)");
    test_rfc7520_signature(&key, "rfc7520_figure15.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 15)");

    // 4.2 "PS256"
    test_rfc7520_signature(&key, "rfc7520_figure20.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 20)");
    test_rfc7520_signature(&key, "rfc7520_figure21.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 21)");
    test_rfc7520_signature(&key, "rfc7520_figure22.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 22)");

    // 4.3 "ES256"
    test_rfc7520_signature(&key, "rfc7520_figure27.jws", "RFC 7520 4.3.  ECDSA Signature (figure 27)");
    test_rfc7520_signature(&key, "rfc7520_figure28.jws", "RFC 7520 4.3.  ECDSA Signature (figure 28)");
    test_rfc7520_signature(&key, "rfc7520_figure29.jws", "RFC 7520 4.3.  ECDSA Signature (figure 29)");

    // 4.4 "HS256"
    test_rfc7520_signature(&key, "rfc7520_figure34.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 34)");
    test_rfc7520_signature(&key, "rfc7520_figure35.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 35)");
    test_rfc7520_signature(&key, "rfc7520_figure36.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 36)");

    // 4.5.  Signature with Detached Content
    // 4.6.  Protecting Specific Header Fields
    test_rfc7520_signature(&key, "rfc7520_figure49.jws", "RFC 7520 4.6.  Protecting Specific Header Fields (figure 49)");
    test_rfc7520_signature(&key, "rfc7520_figure50.jws", "RFC 7520 4.6.  Protecting Specific Header Fields (figure 50)");

    // 4.7.  Protecting Content Only
    test_rfc7520_signature(&key, "rfc7520_figure54.jws", "RFC 7520 4.7.  Protecting Content Only (figure 54)");
    test_rfc7520_signature(&key, "rfc7520_figure55.jws", "RFC 7520 4.7.  Protecting Content Only (figure 55)");

    // 4.8.  Multiple Signatures
    test_rfc7520_signature(&key, "rfc7520_figure61.jws", "RFC 7520 4.8.  Multiple Signatures #1 (figure 61)");
    test_rfc7520_signature(&key, "rfc7520_figure65.jws", "RFC 7520 4.8.  Multiple Signatures #2 (figure 65)");
    test_rfc7520_signature(&key, "rfc7520_figure70.jws", "RFC 7520 4.8.  Multiple Signatures #3 (figure 70)");
    test_rfc7520_signature(&key, "rfc7520_figure71.jws", "RFC 7520 4.8.  Multiple Signatures (figure 71)");

    // 5.1 "RSA1_5" "A128CBC-HS256"
    test_rfc7520_jwe(&key, "rfc7520_figure81.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 81)");
    test_rfc7520_jwe(&key, "rfc7520_figure82.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 82)");
    test_rfc7520_jwe(&key, "rfc7520_figure83.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 83)");
    // 5.2 "RSA-OAEP" "A256GCM"
    test_rfc7520_jwe(&key, "rfc7520_figure92.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 92)");
    test_rfc7520_jwe(&key, "rfc7520_figure93.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 93)");
    test_rfc7520_jwe(&key, "rfc7520_figure94.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 94)");
    // 5.3 "PBES2-HS512+A256KW" "A128CBC-HS256"
    crypto_key crypto_key2;
    crypto_keychain keygen;
    binary_t password_figure96;
    // entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun
    const char* figure96 =
        "entrap_o\xe2\x80\x93"
        "peter_long\xe2\x80\x93"
        "credit_tun";
    keygen.add_oct(&crypto_key2, jwa_t::jwa_pbes2_hs512_a256kw, str2bin(figure96), keydesc(crypto_use_t::use_enc));
    test_rfc7520_jwe(&crypto_key2, "rfc7520_figure105.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 105)");
    test_rfc7520_jwe(&crypto_key2, "rfc7520_figure106.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 106)");
    test_rfc7520_jwe(&crypto_key2, "rfc7520_figure107.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 107)");
    // 5.4 "ECDH-ES+A128KW" "A256GCM"
    test_rfc7520_jwe(&key, "rfc7520_figure117.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 117)");
    test_rfc7520_jwe(&key, "rfc7520_figure118.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 118)");
    test_rfc7520_jwe(&key, "rfc7520_figure119.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 119)");
    // 5.5 "ECDH-ES" "A128CBC-HS256"
    test_rfc7520_jwe(&key, "rfc7520_figure128.jwe", "RFC 7520 5.5.  Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2 (figure 128)");
    test_rfc7520_jwe(&key, "rfc7520_figure129.jwe", "RFC 7520 5.5.  Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2 (figure 129)");
    // 5.6 "dir" "A256GCM"
    test_rfc7520_jwe(&key, "rfc7520_figure136.jwe", "RFC 7520 5.6.  Direct Encryption Using AES-GCM (figure 136)");
    test_rfc7520_jwe(&key, "rfc7520_figure137.jwe", "RFC 7520 5.6.  Direct Encryption Using AES-GCM (figure 137)");
    // 5.7 "A256GCMKW" "A128CBC-HS256"
    test_rfc7520_jwe(&key, "rfc7520_figure148.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 148)");
    test_rfc7520_jwe(&key, "rfc7520_figure149.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 149)");
    test_rfc7520_jwe(&key, "rfc7520_figure150.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 150)");
    // 5.8 "A128KW" "A256GCM"
    test_rfc7520_jwe(&key, "rfc7520_figure159.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 159)");
    test_rfc7520_jwe(&key, "rfc7520_figure160.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 160)");
    test_rfc7520_jwe(&key, "rfc7520_figure161.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 161)");

    // 5.9 Compressed Content
    test_rfc7520_jwe(&key, "rfc7520_figure170.jwe", "RFC 7520 5.9.  Compressed Content (figure 170)");
    test_rfc7520_jwe(&key, "rfc7520_figure171.jwe", "RFC 7520 5.9.  Compressed Content (figure 171)");
    test_rfc7520_jwe(&key, "rfc7520_figure172.jwe", "RFC 7520 5.9.  Compressed Content (figure 172)");

    // 5.10.  Including Additional Authenticated Data
    test_rfc7520_jwe(&key, "rfc7520_figure182.jwe", "RFC 7520 5.10.  Including Additional Authenticated Data (figure 182)");
    test_rfc7520_jwe(&key, "rfc7520_figure183.jwe", "RFC 7520 5.10.  Including Additional Authenticated Data (figure 183)");

    // 5.11.  Protecting Specific Header Fields
    test_rfc7520_jwe(&key, "rfc7520_figure192.jwe", "RFC 7520 5.11.  Protecting Specific Header Fields (figure 192)");
    test_rfc7520_jwe(&key, "rfc7520_figure193.jwe", "RFC 7520 5.11.  Protecting Specific Header Fields (figure 193)");

    // 5.12.  Protecting Content Only
    test_rfc7520_jwe(&key, "rfc7520_figure200.jwe", "RFC 7520 5.12.  Protecting Content Only (figure 200)");
    test_rfc7520_jwe(&key, "rfc7520_figure201.jwe", "RFC 7520 5.12.  Protecting Content Only (figure 201)");

    // 5.13.  Encrypting to Multiple Recipients
    test_rfc7520_jwe(&key, "rfc7520_figure221.jwe", "RFC 7520 5.13.  General JWE JSON Serialization (figure 221)");
}

void test_rfc7520_6_nesting_sig_and_enc() {
    print_text("RFC 7520 6.  Nesting Signatures and Encryption");
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7520_6.jwk");
    key.for_each(dump_crypto_key, nullptr);

    // 6.  Nesting Signatures and Encryption
    test_rfc7520_signature(&key, "rfc7520_figure228.jws", "RFC 7520 6.  Nesting Signatures and Encryption (figure 228)");
    test_rfc7520_jwe(&key, "rfc7520_figure236.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 236)");
    test_rfc7520_jwe(&key, "rfc7520_figure237.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 237)");
    test_rfc7520_jwe(&key, "rfc7520_figure238.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 238)");
}

void test_jwe_flattened() {
    print_text("JWE");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    json_web_signature jws;
    crypto_key crypto_pubkey;
    crypto_key crypto_privkey;

    jose_context_t* handle_encrypt = nullptr;
    jose_context_t* handle_decrypt = nullptr;
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    std::string encrypted;
    binary_t output;
    bool result = false;
    basic_stream bs;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        jwk.load_file(&crypto_pubkey, key_ownspec, "rfc7520_pub.jwk");
        jwk.load_file(&crypto_privkey, key_ownspec, "rfc7520_priv.jwk");

        crypto_pubkey.for_each(dump_crypto_key, nullptr);
        crypto_privkey.for_each(dump_crypto_key, nullptr);

        jose.open(&handle_encrypt, &crypto_pubkey);
        jose.open(&handle_decrypt, &crypto_privkey);

        jwe_t encs[] = {
            jwe_t::jwe_a128cbc_hs256, jwe_t::jwe_a192cbc_hs384, jwe_t::jwe_a256cbc_hs512, jwe_t::jwe_a128gcm, jwe_t::jwe_a192gcm, jwe_t::jwe_a256gcm,
        };
        jwa_t algs[] = {
            jwa_t::jwa_rsa_1_5,
            jwa_t::jwa_rsa_oaep,
            jwa_t::jwa_rsa_oaep_256,
            jwa_t::jwa_a128kw,
            jwa_t::jwa_a192kw,
            jwa_t::jwa_a256kw,
            jwa_t::jwa_dir,
            jwa_t::jwa_ecdh_es,
            jwa_t::jwa_ecdh_es_a128kw,
            jwa_t::jwa_ecdh_es_a192kw,
            jwa_t::jwa_ecdh_es_a256kw,
            jwa_t::jwa_a128gcmkw,
            jwa_t::jwa_a192gcmkw,
            jwa_t::jwa_a256gcmkw,
            jwa_t::jwa_pbes2_hs256_a128kw,
            jwa_t::jwa_pbes2_hs384_a192kw,
            jwa_t::jwa_pbes2_hs512_a256kw,
        };

        for (size_t i = 0; i < RTL_NUMBER_OF(encs); i++) {
            jwe_t enc = encs[i];
            const char* nameof_enc = advisor->nameof_jose_encryption(encs[i]);

            for (size_t j = 0; j < RTL_NUMBER_OF(algs); j++) {
                jwa_t alg = algs[j];
                const char* nameof_alg = advisor->nameof_jose_algorithm(algs[j]);
                if (nameof_alg) {
                    print_text("JWE enc %s alg %s", nameof_enc, nameof_alg);

                    ret = jose.encrypt(handle_encrypt, enc, alg, str2bin(input), encrypted, jose_serialization_t::jose_flatjson);
                    if (errorcode_t::success == ret) {
                        dump("encrypted", encrypted);

                        ret = jose.decrypt(handle_decrypt, encrypted, output, result);
                        dump2("decrypted", output);
                    }
                    _test_case.test(ret, __FUNCTION__, "RFC 7520 JWE enc %s alg %s", nameof_enc, nameof_alg);
                }
            }
        }
    }
    __finally2 {
        jose.close(handle_encrypt);
        jose.close(handle_decrypt);
    }
}

void test_jwe_json(jwe_t enc) {
    print_text("JWE");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    json_web_signature jws;
    crypto_key crypto_pubkey;
    crypto_key crypto_privkey;

    jose_context_t* handle_encrypt = nullptr;
    jose_context_t* handle_decrypt = nullptr;
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    std::string encrypted;
    binary_t output;
    bool result = false;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    const char* nameof_enc = advisor->nameof_jose_encryption(enc);

    __try2 {
        jwk.load_file(&crypto_pubkey, key_ownspec, "rfc7520_pub.jwk");
        jwk.load_file(&crypto_privkey, key_ownspec, "rfc7520_priv.jwk");

        crypto_pubkey.for_each(dump_crypto_key, nullptr);
        crypto_privkey.for_each(dump_crypto_key, nullptr);

        jose.open(&handle_encrypt, &crypto_pubkey);
        jose.open(&handle_decrypt, &crypto_privkey);
        std::list<jwa_t> algs;

        algs.push_back(jwa_t::jwa_rsa_1_5);
        algs.push_back(jwa_t::jwa_rsa_oaep);
        algs.push_back(jwa_t::jwa_rsa_oaep_256);
        algs.push_back(jwa_t::jwa_a128kw);
        algs.push_back(jwa_t::jwa_a192kw);
        algs.push_back(jwa_t::jwa_a256kw);
        algs.push_back(jwa_t::jwa_dir);
        // algs.push_back (jwa_t::jwa_ecdh_es);
        algs.push_back(jwa_t::jwa_ecdh_es_a128kw);
        algs.push_back(jwa_t::jwa_ecdh_es_a192kw);
        algs.push_back(jwa_t::jwa_ecdh_es_a256kw);
        algs.push_back(jwa_t::jwa_a128gcmkw);
        algs.push_back(jwa_t::jwa_a192gcmkw);
        algs.push_back(jwa_t::jwa_a256gcmkw);
        algs.push_back(jwa_t::jwa_pbes2_hs256_a128kw);
        algs.push_back(jwa_t::jwa_pbes2_hs384_a192kw);
        algs.push_back(jwa_t::jwa_pbes2_hs512_a256kw);

        print_text("JWE enc %s", nameof_enc);

        ret = jose.encrypt(handle_encrypt, enc, algs, str2bin(input), encrypted, jose_serialization_t::jose_json);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        dump("encrypted", encrypted);

        ret = jose.decrypt(handle_decrypt, encrypted, output, result);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        jose.close(handle_encrypt);
        jose.close(handle_decrypt);
    }
    _test_case.test(ret, __FUNCTION__, "RFC 7520 JWE enc %s", nameof_enc);
}

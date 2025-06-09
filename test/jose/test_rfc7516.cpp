/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

return_t do_test_jose_file(crypto_key* key, const char* file, bool& result) {
    return_t ret = errorcode_t::success;

    __try2 {
        result = false;

        if (nullptr == key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(file);
        if (errorcode_t::success == ret) {
            fs.begin_mmap();

            json_object_signing_encryption jose;
            jose_context_t* jose_context = nullptr;
            binary_t source;

            jose.open(&jose_context, key);
            ret = jose.decrypt(jose_context, std::string((char*)fs.data(), fs.size()), source, result);
            jose.close(jose_context);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_rfc7516_A1_test() {
    print_text("RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM");

    // A.1.1.  JOSE Header
    std::string jose_header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
    // eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
    // A.1.2.  Content Encryption Key (CEK)
    constexpr byte_t cek[] = {177, 161, 244, 128, 84,  143, 225, 115, 63, 180, 3,   255, 107, 154, 212, 246,
                              138, 7,   110, 91,  112, 46,  34,  105, 47, 130, 203, 46,  122, 234, 64,  252};
    // A.1.3.  Key Encryption
    // see rfc7516_A1.jwk
    constexpr byte_t encrypted_key[] = {
        56,  163, 154, 192, 58,  53,  222, 4,   105, 218, 136, 218, 29,  94,  203, 22,  150, 92,  129, 94,  211, 232, 53,  89,  41,  60,  138, 56,  196,
        216, 82,  98,  168, 76,  37,  73,  70,  7,   36,  8,   191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4,   117, 141, 230, 199, 247, 173, 45,
        182, 214, 74,  177, 107, 211, 153, 11,  205, 196, 171, 226, 162, 128, 171, 182, 13,  237, 239, 99,  193, 4,   91,  219, 121, 223, 107, 167, 61,
        119, 228, 173, 156, 137, 134, 200, 80,  219, 74,  253, 56,  185, 91,  177, 34,  158, 89,  154, 205, 96,  55,  18,  138, 43,  96,  218, 215, 128,
        124, 75,  138, 243, 85,  25,  109, 117, 140, 26,  155, 249, 67,  167, 149, 231, 100, 6,   41,  65,  214, 251, 232, 87,  72,  40,  182, 149, 154,
        168, 31,  193, 126, 215, 89,  28,  111, 219, 125, 182, 139, 235, 195, 197, 23,  234, 55,  58,  63,  180, 68,  202, 206, 149, 75,  205, 248, 176,
        67,  39,  178, 60,  98,  193, 32,  238, 122, 96,  158, 222, 57,  183, 111, 210, 55,  188, 215, 206, 180, 166, 150, 166, 106, 250, 55,  229, 72,
        40,  69,  214, 216, 104, 23,  40,  135, 212, 28,  127, 41,  80,  175, 174, 168, 115, 171, 197, 89,  116, 92,  103, 246, 83,  216, 182, 176, 84,
        37,  147, 35,  45,  219, 172, 99,  226, 233, 73,  37,  124, 42,  72,  49,  242, 35,  127, 184, 134, 117, 114, 135, 206};
    // OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
    // ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
    // Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
    // mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
    // 1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
    // 6UklfCpIMfIjf7iGdXKHzg

    // A.1.4.  Initialization Vector
    byte_t iv[] = {227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219};
    // 48V1_ALb6US04U3b

    // A.1.5.  Additional Authenticated Data
    byte_t aad[] = {101, 121, 74,  104, 98,  71, 99,  105, 79, 105, 74,  83, 85,  48, 69, 116, 84, 48, 70, 70, 85,  67,  73,
                    115, 73,  109, 86,  117, 89, 121, 73,  54, 73,  107, 69, 121, 78, 84, 90,  72, 81, 48, 48, 105, 102, 81};
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    // see A.1.1

    // A.1.6.  Content Encryption
    byte_t ciphertext[] = {229, 236, 166, 241, 53,  191, 115, 196, 174, 43,  73,  109, 39,  122, 233, 96,  140, 206, 120, 52, 51,
                           237, 48,  11,  190, 219, 186, 80,  111, 104, 50,  142, 47,  167, 59,  61,  181, 127, 196, 21,  40, 82,
                           242, 32,  123, 143, 168, 226, 73,  216, 176, 144, 138, 247, 106, 60,  16,  205, 160, 109, 64,  63, 192};
    // 5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
    // SdiwkIr3ajwQzaBtQD_A
    byte_t tag[] = {92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145};
    // XFBoMYUZodetZdvTiFvSkQ

    // A.1.7.  Complete Representation
    // BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    // BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
    // Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE
    // Authentication Tag)
    // eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
    // OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
    // ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
    // Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
    // mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
    // 1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
    // 6UklfCpIMfIjf7iGdXKHzg.
    // 48V1_ALb6US04U3b.
    // 5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
    // SdiwkIr3ajwQzaBtQD_A.
    // XFBoMYUZodetZdvTiFvSkQ

    bool result = false;
    openssl_crypt crypt;
    crypt_context_t* crypt_handle;
    binary_t plain;
    binary_t aad_data;
    binary_t tag_data;
    binary_t tag_gen;
    binary_t encrypted_key_data;
    binary_t decrypted_key_data;
    basic_stream bs;
    crypto_key key;
    json_web_key jwk;
    const EVP_PKEY* pkey;
    std::string kid;
    std::string jose_header_encoded;
    std::string encrypted_key_encoded;
    std::string iv_encoded;
    std::string ciphertext_encoded;
    std::string tag_encoded;
    // binary_t aad_decoded;
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    binary_t data;

    jwk.load_file(&key, key_ownspec, "rfc7516_A1.jwk");
    key.for_each(dump_crypto_key, nullptr);

    dump2("input", input);
    dump2("jose_header", jose_header);
    dump2("cek", cek, RTL_NUMBER_OF(cek));
    dump2("encrypted_key", encrypted_key, RTL_NUMBER_OF(encrypted_key));
    dump2("iv", iv, RTL_NUMBER_OF(iv));
    dump2("aad", aad, RTL_NUMBER_OF(aad));
    dump2("ciphertext", ciphertext, RTL_NUMBER_OF(ciphertext));
    dump2("tag", tag, RTL_NUMBER_OF(tag));

    // A.1.1
    jose_header_encoded = std::move(base64_encode((byte_t*)jose_header.c_str(), jose_header.size(), encoding_t::encoding_base64url));
    dump("jose_header_encoded", jose_header_encoded);
    // A.1.3
    encrypted_key_encoded = std::move(base64_encode(encrypted_key, RTL_NUMBER_OF(encrypted_key), encoding_t::encoding_base64url));
    dump("encrypted_key_encoded", encrypted_key_encoded);

    encrypted_key_data.insert(encrypted_key_data.end(), encrypted_key, encrypted_key + RTL_NUMBER_OF(encrypted_key));
    pkey = key.select(kid, crypto_use_t::use_enc);
    json_object_signing_encryption jose;
    crypt.decrypt(pkey, encrypted_key_data, decrypted_key_data, crypt_enc_t::rsa_oaep);
    dump2("decrypted_key", decrypted_key_data);

    if ((decrypted_key_data.size() == RTL_NUMBER_OF(cek)) && (0 == memcmp(&decrypted_key_data[0], cek, RTL_NUMBER_OF(cek)))) {
        result = true;
    } else {
        result = false;
    }
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                    "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.3)");

    // A.1.4
    dump_b64url("iv_encoded", iv, RTL_NUMBER_OF(iv));
    // A.1.5
    aad_data.insert(aad_data.end(), aad, aad + RTL_NUMBER_OF(aad));
    if ((jose_header_encoded.size() == RTL_NUMBER_OF(aad)) && (0 == memcmp(jose_header_encoded.c_str(), aad, RTL_NUMBER_OF(aad)))) {
        result = true;
    } else {
        result = false;
    }
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                    "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.5)");
    // A.1.6

    tag_data.insert(tag_data.end(), tag, tag + RTL_NUMBER_OF(tag));
    crypt.open(&crypt_handle, crypt_algorithm_t::aes256, crypt_mode_t::gcm, cek, RTL_NUMBER_OF(cek), iv, RTL_NUMBER_OF(iv));
    // tag from plain, aad
    crypt.encrypt(crypt_handle, (byte_t*)input.c_str(), input.size(), data, aad_data, tag_gen);
    dump2("data", data);
    dump2("tag", tag_gen);
    if ((tag_gen.size() == RTL_NUMBER_OF(tag)) && (0 == memcmp(&tag_gen[0], tag, RTL_NUMBER_OF(tag)))) {
        result = true;
    } else {
        result = false;
    }
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                    "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.6, tag)");
    if ((data.size() == RTL_NUMBER_OF(ciphertext)) && (0 == memcmp(&data[0], ciphertext, RTL_NUMBER_OF(ciphertext)))) {
        result = true;
    } else {
        result = false;
    }
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                    "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.6, ciphertext)");

    // plain from ciphertext, aad, tag
    crypt.decrypt(crypt_handle, ciphertext, RTL_NUMBER_OF(ciphertext), plain, aad_data, tag_data);
    dump2("plain", plain);

    dump_b64url("ciphertext_encoded", data);
    dump_b64url("ta_encoded", tag_gen);

    crypt.close(crypt_handle);

    // A.1.7
    dump("header", jose_header_encoded);
    dump("key", encrypted_key_encoded);
    dump("iv", iv_encoded);
    dump("ciphertext", ciphertext_encoded);
    dump("tag", tag_encoded);
}

void test_rfc7516_A1() {
    // return_t ret = errorcode_t::success;

    print_text("RFC 7516 A.1");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7516_A1.jwk");
    key.for_each(dump_crypto_key, nullptr);

    std::string jose_header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open(&context, &key);

    jose.encrypt(context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, str2bin(input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, compact, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (compact)");

    jose.encrypt(context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, str2bin(input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt(context, json_flat, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (flat)");

    jose.encrypt(context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, str2bin(input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt(context, json_serial, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (json)");

    jose.close(context);

    dump("RFC 7516 A.1. compact", compact);
    dump("RFC 7516 A.1. flattened JSON serialization", json_flat);
    dump("RFC 7516 A.1. JSON serialization", json_serial);

    ret = do_test_jose_file(&key, "rfc7516_A1.jws", result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (file)");
}

void test_rsa_oaep() {
    print_text("RFC 7516 A.1 RSA-OAEP");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file(&key, key_ownspec, "rfc7516_A1.jwk");
    key.for_each(dump_crypto_key, nullptr);

    std::string input = "The true sign of intelligence is not knowledge but imagination.";

    jose.open(&context, &key);
    jose.encrypt(context, jwe_t::jwe_a128gcm, jwa_t::jwa_rsa_oaep, str2bin(input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, output, plain, result);
    jose.close(context);

    dump("encrypted", output);

    _test_case.test(ret, __FUNCTION__, "RSA-OAEP");
}

void test_rsa_oaep_256() {
    print_text("RFC 7516 A.1 RSA-OAEP-256");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file(&key, key_ownspec, "rfc7516_A1.jwk");
    key.for_each(dump_crypto_key, nullptr);

    std::string jose_header = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}";
    std::string input = "The true sign of intelligence is not knowledge but imagination.";

    jose.open(&context, &key);
    jose.encrypt(context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep_256, str2bin(input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, output, plain, result);
    jose.close(context);

    dump("encrypted", output);

    _test_case.test(ret, __FUNCTION__, "RSA-OAEP-256");
}

void test_rfc7516_A2() {
    // return_t ret = errorcode_t::success;

    print_text("RFC 7516 A.2");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7516_A2.jwk");
    key.for_each(dump_crypto_key, nullptr);

    // std::string jose_header = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}";
    std::string input = "Live long and prosper.";
    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open(&context, &key);

    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, str2bin(input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, compact, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (compact)");

    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, str2bin(input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt(context, compact, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (flat)");

    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, str2bin(input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt(context, compact, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (json)");

    jose.close(context);

    dump("RFC 7516 A.2. compact", compact);
    dump("RFC 7516 A.2. flattened JSON serialization", json_flat);
    dump("RFC 7516 A.2. JSON serialization", json_serial);

    ret = do_test_jose_file(&key, "rfc7516_A2.jws", result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (file)");
}

void test_rfc7516_A3() {
    print_text("RFC 7516 A.3");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7516_A3.jwk");
    key.for_each(dump_crypto_key, nullptr);

    // std::string jose_header = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
    std::string input = "Live long and prosper.";

    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open(&context, &key);
    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, str2bin(input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, compact, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (compact)");
    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, str2bin(input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt(context, json_flat, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (flat)");
    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, str2bin(input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt(context, json_serial, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (json)");
    jose.close(context);

    dump("RFC 7516 A.3. compact", compact);
    dump("RFC 7516 A.3. flattened JSON serialization", json_flat);
    dump("RFC 7516 A.3. JSON serialization", json_serial);

    ret = do_test_jose_file(&key, "rfc7516_A3.jws", result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (file)");
}

void test_rfc7516_A4() {
    // return_t ret = errorcode_t::success;

    print_text("RFC 7516 A.4");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc7516_A4.jwk");
    key.for_each(dump_crypto_key, nullptr);

    std::string input = "Live long and prosper.";
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open(&context, &key);
    std::list<jwa_t> algs;
    // algs.push_back (jwa_t::jwa_rsa_1_5);
    // algs.push_back (jwa_t::jwa_a128kw);
    algs.push_back(jwa_t::jwa_pbes2_hs256_a128kw);
    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, algs, str2bin(input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt(context, json_serial, source, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.4. JWE Using General JWE JSON Serialization (json)");
    jose.close(context);

    dump("RFC 7516 A.4", json_serial);

    ret = do_test_jose_file(&key, "rfc7516_A4.jws", result);
    _test_case.test(ret, __FUNCTION__, "RFC 7516 A.4. JWE Using General JWE JSON Serialization (file)");
}

void test_rfc7516_B() {
    return_t ret = errorcode_t::success;

    print_text("RFC 7516 B Example AES_128_CBC_HMAC_SHA_256 Computation");

    openssl_crypt crypt;
    openssl_hash hash;
    crypt_context_t* crypt_handle;
    hash_context_t* hash_handle;
    basic_stream bs;
    binary_t enc_value;
    binary_t test;
    binary_t hmac_value;

    // B.1.  Extract MAC_KEY and ENC_KEY from Key
    // 256 bits key
    // first 128 bits HMAC SHA-256 key (MAC_KEY)
    // last 128 bits AES-CBC key (ENC_KEY)
    constexpr byte_t key[] = {4,   211, 31,  197, 84,  157, 252, 254, 11,  100, 157, 250, 63,  170, 106, 206,
                              107, 124, 212, 45,  111, 107, 9,   219, 200, 177, 0,   240, 143, 156, 44,  207};
    // B.2.  Encrypt Plaintext to Create Ciphertext
    constexpr byte_t plain[] = {76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46};
    constexpr byte_t encrypted_data[] = {40,  57,  83,  181, 119, 33, 133, 148, 198, 185, 243, 24,  152, 230, 6,  75,
                                         129, 223, 127, 19,  210, 82, 183, 230, 168, 33,  215, 104, 143, 112, 56, 102};
    // B.3.  64-Bit Big-Endian Representation of AAD Length
    constexpr byte_t aad[] = {101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83,  49, 99, 105, 76, 67, 74, 108, 98, 109,
                              77,  105, 79, 105, 74, 66, 77, 84,  73, 52,  81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48};
    constexpr byte_t concat_sample[] = {101, 121, 74,  104, 98,  71,  99,  105, 79,  105, 74,  66,  77, 84,  73,  52,  83,  49,  99,  105, 76,  67,
                                        74,  108, 98,  109, 77,  105, 79,  105, 74,  66,  77,  84,  73, 52,  81,  48,  74,  68,  76,  85,  104, 84,
                                        77,  106, 85,  50,  73,  110, 48,  3,   22,  60,  12,  43,  67, 104, 105, 108, 108, 105, 99,  111, 116, 104,
                                        101, 40,  57,  83,  181, 119, 33,  133, 148, 198, 185, 243, 24, 152, 230, 6,   75,  129, 223, 127, 19,  210,
                                        82,  183, 230, 168, 33,  215, 104, 143, 112, 56,  102, 0,   0,  0,   0,   0,   0,   1,   152};
    uint64 al = hton64(RTL_NUMBER_OF(aad) * 8);
    // B.4.  Initialization Vector Value
    constexpr byte_t iv[] = {3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101};
    // B.5.  Create Input to HMAC Computation
    // B.6.  Compute HMAC Value
    // B.7.  Truncate HMAC Value to Create Authentication Tag
    constexpr byte_t tag[] = {83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85};

    // compute
    __try2 {
        dump2("key", key, RTL_NUMBER_OF(key));
        dump2("plain", plain, RTL_NUMBER_OF(plain));
        dump2("iv", iv, RTL_NUMBER_OF(iv));

        // B.2
        crypt.open(&crypt_handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, key + 16, 16, iv, 16);
        crypt.encrypt(crypt_handle, plain, RTL_NUMBER_OF(plain), enc_value);
        dump2("encryption result (computed)", enc_value);
        // if (encryption result = encrypted_data) then success
        // test vice versa now
        dump2("encryption result (rfc sample)", encrypted_data, RTL_NUMBER_OF(encrypted_data));
        crypt.decrypt(crypt_handle, encrypted_data, RTL_NUMBER_OF(encrypted_data), test);
        dump2("decrypt the encryption result (rfc sample)", test);
        // B.5
        binary_t concat;  // concatenate AAD, IV, CT, AL
        concat.insert(concat.end(), aad, aad + RTL_NUMBER_OF(aad));
        concat.insert(concat.end(), iv, iv + RTL_NUMBER_OF(iv));
        concat.insert(concat.end(), enc_value.begin(), enc_value.end());
        concat.insert(concat.end(), (byte_t*)&al, (byte_t*)&al + sizeof(int64));
        dump2("concat", concat);
        dump2("concat (rfc sample)", concat_sample, RTL_NUMBER_OF(concat_sample));
        // B.6
        hash.open(&hash_handle, hash_algorithm_t::sha2_256, key, 16);
        hash.hash(hash_handle, &concat[0], concat.size(), hmac_value);

        dump2("hmac_value", hmac_value);

        constexpr byte_t hmac_sample[] = {83, 73, 191, 98,  104, 205, 211, 128, 201, 189, 199, 133, 32,  38, 194, 85,
                                          9,  84, 229, 201, 219, 135, 44,  252, 145, 102, 179, 140, 105, 86, 229, 116};
        dump2("hmac (rfc sample)", hmac_sample, RTL_NUMBER_OF(hmac_sample));

        // B.7
        binary_t trunc;
        trunc.insert(trunc.end(), &hmac_value[0], &hmac_value[0] + 16);
        dump2("trunc", trunc);

        if ((RTL_NUMBER_OF(tag) == trunc.size()) && (0 == memcmp(&trunc[0], tag, trunc.size()))) {
            // do nothing
        } else {
            ret = errorcode_t::internal_error;
        }
        _test_case.test(ret, __FUNCTION__, "RFC 7516 B.  Example AES_128_CBC_HMAC_SHA_256 Computation");
    }
    __finally2 {
        crypt.close(crypt_handle);
        hash.close(hash_handle);
    }

    __try2 {
        binary_t bin_pt;
        binary_t bin_ct;
        binary_t bin_t;
        binary_t bin_key;
        binary_t bin_iv;
        binary_t bin_aad;
        binary_t bin_plain;
        binary_t bin_cipher;
        binary_t bin_tag;

        binary_append(bin_key, key, RTL_NUMBER_OF(key));
        binary_append(bin_iv, iv, RTL_NUMBER_OF(iv));
        binary_append(bin_aad, aad, RTL_NUMBER_OF(aad));
        binary_append(bin_plain, plain, RTL_NUMBER_OF(plain));
        binary_append(bin_cipher, encrypted_data, RTL_NUMBER_OF(encrypted_data));
        binary_append(bin_tag, tag, RTL_NUMBER_OF(tag));

        crypto_cbc_hmac cbchmac;

        binary_t enckey;
        binary_t mackey;

        cbchmac.set_enc(aes128).set_mac(sha2_256).set_flag(jose_encrypt_then_mac);
        cbchmac.split_key(bin_key, enckey, mackey);

        cbchmac.encrypt(enckey, mackey, bin_iv, bin_aad, bin_plain, bin_ct, bin_t);

        _logger->hdump("ciphertext", bin_ct, 16, 3);
        _logger->hdump("tag", bin_t, 16, 3);
        _test_case.assert(bin_ct == bin_cipher, __FUNCTION__, "cbc_hmac_etm_encrypt");
        _test_case.assert(bin_t == bin_tag, __FUNCTION__, "cbc_hmac_etm_encrypt");

        cbchmac.decrypt(enckey, mackey, bin_iv, bin_aad, bin_ct, bin_pt, bin_t);

        _logger->hdump("plaintext", bin_pt, 16, 3);
        _test_case.assert(bin_pt == bin_plain, __FUNCTION__, "cbc_hmac_etm_decrypt");
    }
    __finally2 {}
}

void test_jwk() {
    // preserve leading zero while loading key

    // RFC 7520 "kid": "bilbo.baggins@hobbiton.example"
    //
    // original (leading zero preserved)
    //   AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt
    //   0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad
    //
    //   to preserve leading zero
    //   crypto_key::get_key(key->pkey, mapper->flag, item.type, item.pub1, item.pub2, item.priv, true);
    //
    // sample (leading zero not preserved)
    //   cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0
    //   72992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad
    //
    //   crypto_key::get_key(key->pkey, mapper->flag, item.type, item.pub1, item.pub2, item.priv, false);
}

/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_basic() {
    print_text("basic informations");
    const OPTION option = _cmdline->value();

    struct {
        const char* name;
        const EVP_CIPHER* evp;
    } table[] = {
        {
            "EVP_aes128_wrap",
            EVP_aes_128_wrap(),
        },
        {
            "EVP_aes192_wrap",
            EVP_aes_192_wrap(),
        },
        {
            "EVP_aes256_wrap",
            EVP_aes_256_wrap(),
        },
        {
            "EVP_aes128_gcm",
            EVP_aes_128_gcm(),
        },
        {
            "EVP_aes192_gcm",
            EVP_aes_192_gcm(),
        },
        {
            "EVP_aes256_gcm",
            EVP_aes_256_gcm(),
        },
        {
            "EVP_aes128_cbc",
            EVP_aes_128_cbc(),
        },
        {
            "EVP_aes192_cbc",
            EVP_aes_192_cbc(),
        },
        {
            "EVP_aes256_cbc",
            EVP_aes_256_cbc(),
        },
    };

    {
        basic_stream bs;
        for (size_t i = 0; i < RTL_NUMBER_OF(table); i++) {
            int key_len = EVP_CIPHER_key_length(table[i].evp);
            int iv_len = EVP_CIPHER_iv_length(table[i].evp);

            bs << table[i].name << " key " << key_len << " iv " << iv_len << "\n";
        }
        _logger->write(bs);
    }

#if __cplusplus >= 201103L  // c++11
    {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        basic_stream bs;

        std::function<void(const hint_jose_encryption_t*, void*)> lambda1 = [&](const hint_jose_encryption_t* item, void* user) -> void {
            bs.printf("    %s\n", item->alg_name);
        };
        std::function<void(const hint_signature_t*, void*)> lambda2 = [&](const hint_signature_t* item, void* user) -> void {
            bs.printf("    %s\n", item->jws_name);
        };
        _logger->write(bs);

        _logger->writeln("JWA");
        advisor->jose_for_each_algorithm(lambda1, nullptr);

        _logger->writeln("JWE");
        advisor->jose_for_each_encryption(lambda1, nullptr);

        _logger->writeln("JWS");
        advisor->jose_for_each_signature(lambda2, nullptr);
    }
#endif

    {
        _logger->writeln("jwk test");

        basic_stream bs;
        json_web_key jwk;
        json_web_signature jws;

        crypto_key crypto_key_es521;
        jwk.load_file(&crypto_key_es521, key_ownspec, "rfc7516_A4.jwk");

        const EVP_PKEY* pkey = crypto_key_es521.any();
        if (pkey) {
            if (option.verbose) {
                basic_stream bs;
                dump_key(pkey, &bs);
                bs.printf("%s\n", bs.c_str());
            }
        }
        _logger->write(bs);

        _test_case.assert(true, __FUNCTION__, "baseic informations");
        _test_case.assert(nullptr != pkey, __FUNCTION__, "jwk");
    }
}

void test_rfc7515_A1() {
    print_text("RFC 7515 A.1");

    constexpr byte_t hs256_header[] = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    std::string rfc_result;

    /* RFC 7515 A.1 Example JWS Using HMAC SHA-256 */
    /* signature:
       eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
       .
       eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
       .
       dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
     */
    rfc_result =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc"
        "GxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    ret = jws.sign(&key, (char*)hs256_header, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS compact) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS compact", signature);
    _test_case.assert(0 == stricmp(rfc_result.c_str(), signature.c_str()), __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS compact) - Verify");

    ret = jws.sign(&key, (char*)hs256_header, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign(&key, (char*)hs256_header, claim, signature, jose_serialization_t::jose_json);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_HS() {
    print_text("RFC 7515 A.1");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_object_signing_encryption jose;
    std::string signature;

    jose_context_t* jose_context = nullptr;
    jose.open(&jose_context, &key);

    ret = jose.sign(jose_context, jws_t::jws_hs256, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Sign");
    ret = jose.verify(jose_context, signature, result);
    dump("JWS Compact", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Verify");

    ret = jose.sign(jose_context, jws_t::jws_hs256, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Sign");
    ret = jose.verify(jose_context, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Verify");

    ret = jose.sign(jose_context, jws_t::jws_hs256, claim, signature, jose_serialization_t::jose_json);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS json) - Sign");
    ret = jose.verify(jose_context, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS json) - Verify");

    jose.close(jose_context);
}

void test_rfc7515_A2() {
    print_text("RFC 7515 A.2");

    /* RFC 7515 */
    constexpr byte_t rs256_header[] = "{\"alg\":\"RS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;
    std::string rfc_result;

    /* RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 */
    /* signature:
       eyJhbGciOiJSUzI1NiJ9
       .
       eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
       .
       cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7
       AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4
       BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K
       0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv
       hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB
       p0igcN_IoypGlUPQGe77Rw
     */
    rfc_result =
        "eyJhbGciOiJSUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
        "p0igcN_IoypGlUPQGe77Rw";

    ret = jws.sign(&key, (char*)rs256_header, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS compact) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS Compact", signature);
    _test_case.assert(0 == stricmp(rfc_result.c_str(), signature.c_str()), __FUNCTION__,
                      "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS compact) - Verify");

    ret = jws.sign(&key, (char*)rs256_header, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign(&key, (char*)rs256_header, claim, signature, jose_serialization_t::jose_json);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_A3() {
    print_text("RFC 7515 A.3");

    /* RFC 7515 */
    constexpr byte_t es256_header[] = "{\"alg\":\"ES256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    /* RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 */
    /* signature:
       eyJhbGciOiJFUzI1NiJ9
       .
       eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
       cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
       .
       DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA
       pmWQxfKTUJqPP3-Kg6NU1Q
     */

    ret = jws.sign(&key, jws_t::jws_es256, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS Compact", signature);
    // result changes
    // so test in https://jwt.io
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Verify");

    ret = jws.sign(&key, jws_t::jws_es256, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Verify");

    ret = jws.sign(&key, jws_t::jws_es256, claim, signature, jose_serialization_t::jose_json);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON serialization) - Verify");

    std::string example;
    example =
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-"
        "F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    dump("Example", example);
    ret = jws.verify(&key, example, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (Example)");
}

void test_rfc7515_A4() {
    print_text("RFC 7515 A.4");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    /* RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 */
    /*
       eyJhbGciOiJFUzUxMiJ9
       .
       UGF5bG9hZA
       .
       AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq
       wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp
       EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn
     */

    // claimconst char payload[] = { 80, 97, 121, 108, 111, 97, 100, 0 };

    ret = jws.sign(&key, jws_t::jws_es512, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS Compact", signature);
    // result changes
    // so test in https://jwt.io
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Verify");

    ret = jws.sign(&key, jws_t::jws_es512, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Verify");

    ret = jws.sign(&key, jws_t::jws_es512, claim, signature, jose_serialization_t::jose_json);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON serialization) - Sign");
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON serialization) - Verify");

    std::string example;
    example =
        "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_"
        "7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";
    dump("Example", example);
    ret = jws.verify(&key, example, result);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (Example)");
}

void test_rfc7515_A5() {
    print_text("RFC 7515 A.5");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    /* RFC 7515 A.5. Example Unsecured JWS */
    /*
       eyJhbGciOiJub25lIn0
       .
       eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
       cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
       .
     */

    constexpr char unsecured_header[] = "{\"alg\":\"none\"}";

    ret = jws.sign(&key, unsecured_header, claim, signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Sign");

    // RFC sample - not support low security reason
    constexpr char sample[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    ret = jws.verify(&key, sample, result);
    dump("JWS Compact", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Verify");
}

void test_rfc7515_A6() {
    print_text("RFC 7515 A.6");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    std::list<jws_t> headers;
    headers.push_back(jws_t::jws_rs256);
    headers.push_back(jws_t::jws_es256);
    jws.sign(&key, headers, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.6. Example JWS Using General JWS JSON Serialization");
}

void test_rfc7515_A7() {
    print_text("RFC 7515 A.7");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign(&key, jws_t::jws_rs256, claim, signature, jose_serialization_t::jose_flatjson);
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7515 A.7. Example JWS Using Flattened JWS JSON Serialization");
}

void test_rfc7515_bypem() {
    print_text("RFC 7515 by PEM");

    constexpr byte_t hs256_header[] = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    constexpr byte_t rs256_header[] = "{\"alg\":\"RS256\"}";
    constexpr byte_t ps256_header[] = "{\"alg\":\"PS256\"}";
    constexpr byte_t es256_header[] = "{\"alg\":\"ES256\"}";
    constexpr byte_t rs384_header[] = "{\"alg\":\"RS384\"}";
    constexpr byte_t ps384_header[] = "{\"alg\":\"PS384\"}";
    constexpr byte_t es384_header[] = "{\"alg\":\"ES384\"}";
    constexpr byte_t rs512_header[] = "{\"alg\":\"RS512\"}";
    constexpr byte_t ps512_header[] = "{\"alg\":\"PS512\"}";
    constexpr byte_t es512_header[] = "{\"alg\":\"ES512\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;

    // NOTE
    // openssl-1.1.1 - ignore PEM HMAC PRIVATE KEY
    jwk.load_file(&key, key_pemfile, "rfc7515.pem");
    jwk.write_file(&key, key_pemfile, "temp.pem");

    json_web_signature jws;
    std::string signature;
    bool result = false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    jws.sign(&key, (char*)hs256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS HS256", signature);
    _test_case.test(ret, __FUNCTION__, "HS256");
#endif

    jws.sign(&key, (char*)rs256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS256", signature);
    _test_case.test(ret, __FUNCTION__, "RS256");

    jws.sign(&key, (char*)es256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS ES256", signature);
    _test_case.test(ret, __FUNCTION__, "ES256");

    jws.sign(&key, (char*)es512_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS ES512", signature);
    _test_case.test(ret, __FUNCTION__, "ES512");

    jws.sign(&key, (char*)ps256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS PS256", signature);
    _test_case.test(ret, __FUNCTION__, "PS256");
}

void test_rfc7515_bykeygen() {
    print_text("RFC 7515 by key generation");

    constexpr byte_t hs256_header[] = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    constexpr byte_t rs256_header[] = R"({"alg":"RS256"})";
    constexpr byte_t ps256_header[] = R"({"alg":"PS256"})";
    constexpr byte_t es256_header[] = R"({"alg":"ES256"})";
    constexpr byte_t rs384_header[] = R"({"alg":"RS384"})";
    constexpr byte_t ps384_header[] = R"({"alg":"PS384"})";
    constexpr byte_t es384_header[] = R"({"alg":"ES384"})";
    constexpr byte_t rs512_header[] = R"({"alg":"RS512"})";
    constexpr byte_t ps512_header[] = R"({"alg":"PS512"})";
    constexpr byte_t es512_header[] = R"({"alg":"ES512"})";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;

    keychain.add_oct(&key, 256, keydesc("sample"));
    keychain.add_rsa(&key, nid_rsa, 2048, keydesc("sample"));
    keychain.add_ec(&key, ec_p256, keydesc("sample"));

    keychain.add_oct(&key, 256, keydesc("HS256"));
    keychain.add_rsa(&key, nid_rsa, 2048, keydesc("RS256"));
    keychain.add_rsa(&key, nid_rsa, 2048, keydesc("RS384"));
    keychain.add_rsa(&key, nid_rsa, 2048, keydesc("RS512"));
    keychain.add_ec(&key, ec_p256, keydesc("ES256"));
    keychain.add_ec(&key, ec_p384, keydesc("ES384"));
    keychain.add_ec(&key, ec_p521, keydesc("ES512"));

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign(&key, (char*)hs256_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS HS256", signature);
    _test_case.test(ret, __FUNCTION__, "HS256");

    jws.sign(&key, (char*)rs256_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS256", signature);
    _test_case.test(ret, __FUNCTION__, "RS256");

    jws.sign(&key, (char*)rs384_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS384", signature);
    _test_case.test(ret, __FUNCTION__, "RS384");

    jws.sign(&key, (char*)rs512_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS512", signature);
    _test_case.test(ret, __FUNCTION__, "RS512");

    jws.sign(&key, (char*)es256_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS ES256", signature);
    _test_case.test(ret, __FUNCTION__, "ES256");

    jws.sign(&key, (char*)ps256_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS PS256", signature);
    _test_case.test(ret, __FUNCTION__, "PS256");

    jws.sign(&key, (char*)rs384_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS384", signature);
    _test_case.test(ret, __FUNCTION__, "RS384");

    jws.sign(&key, (char*)es384_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS ES384", signature);
    _test_case.test(ret, __FUNCTION__, "ES384");

    jws.sign(&key, (char*)ps384_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS PS384", signature);
    _test_case.test(ret, __FUNCTION__, "PS384");

    jws.sign(&key, (char*)rs512_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS RS512", signature);
    _test_case.test(ret, __FUNCTION__, "RS512");

    jws.sign(&key, (char*)es512_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS ES512", signature);
    _test_case.test(ret, __FUNCTION__, "ES512");

    jws.sign(&key, (char*)ps512_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS PS512", signature);
    _test_case.test(ret, __FUNCTION__, "PS512");

    std::list<std::string> headers;
    headers.push_back((char*)hs256_header);
    headers.push_back((char*)rs256_header);
    headers.push_back((char*)es256_header);
    headers.push_back((char*)ps256_header);
    jws.sign(&key, headers, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS HS256,RS256,ES256,PS256", signature);
    _test_case.test(ret, __FUNCTION__, "HS256,RS256,ES256,PS256");
}

void do_key_match(crypto_key* key, jwa_t alg, crypto_use_t use) {
    const EVP_PKEY* pkey = nullptr;
    // size_t key_length = 0;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string kid;
    std::string hex;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm(alg);

    print_text("try kt %d alg %s", alg_info->kty, alg_info->alg_name);
    pkey = key->select(kid, alg, use);
    basic_stream bs;
    if (pkey) {
        const OPTION& option = _cmdline->value();
        if (option.dump_keys) {
            bs.printf("> kid %s\n", kid.c_str());
            key->get_key(pkey, pub1, pub2, priv);

            dump_key(pkey, &bs);
            bs.printf("\n");
        }
    }
    bs.printf(pkey ? "found" : "not found");
    _logger->writeln(bs);
}

void do_key_match(crypto_key* key, jws_t sig, crypto_use_t use) {
    const EVP_PKEY* pkey = nullptr;
    // size_t key_length = 0;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string kid;
    std::string hex;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_signature_t* alg_info = advisor->hintof_jose_signature(sig);

    print_text("try kt %d alg %s", typeof_kty(alg_info), nameof_jws(alg_info));
    pkey = key->select(kid, sig, use);
    basic_stream bs;
    if (pkey) {
        const OPTION& option = _cmdline->value();
        if (option.dump_keys) {
            bs.printf("> kid %s\n", kid.c_str());
            key->get_key(pkey, pub1, pub2, priv);

            dump_key(pkey, &bs);
            bs.printf("\n");
        }
    }
    bs.printf(pkey ? "found" : "not found");
    _logger->writeln(bs);
}

void key_match_test() {
    json_web_key jwk;
    const OPTION& option = _cmdline->value();

    // crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2 {
        crypto_key key;
        jwk.load_file(&key, key_ownspec, "keys.jwk");
        key.for_each(dump_crypto_key, nullptr);

        jwa_t algs[] = {jwa_t::jwa_rsa_1_5,
                        jwa_t::jwa_rsa_oaep,
                        jwa_t::jwa_rsa_oaep_256,
                        jwa_t::jwa_a128kw,
                        jwa_t::jwa_a192kw,
                        jwa_t::jwa_a256kw,
                        jwa_t::jwa_ecdh_es,
                        jwa_t::jwa_ecdh_es_a128kw,
                        jwa_t::jwa_ecdh_es_a192kw,
                        jwa_t::jwa_ecdh_es_a256kw,
                        jwa_t::jwa_a128gcmkw,
                        jwa_t::jwa_a192gcmkw,
                        jwa_t::jwa_a256gcmkw,
                        jwa_t::jwa_pbes2_hs256_a128kw,
                        jwa_t::jwa_pbes2_hs384_a192kw,
                        jwa_t::jwa_pbes2_hs512_a256kw};
        for (unsigned int i = 0; i < RTL_NUMBER_OF(algs); i++) {
            do_key_match(&key, algs[i], crypto_use_t::use_enc);
        }
    }
    __finally2 {}

    __try2 {
        crypto_key key;
        jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
        key.for_each(dump_crypto_key, nullptr);

        jws_t algs[] = {
            jws_t::jws_hs256, jws_t::jws_hs384, jws_t::jws_hs512, jws_t::jws_rs256, jws_t::jws_rs384, jws_t::jws_rs512,
            jws_t::jws_es256, jws_t::jws_es384, jws_t::jws_es512, jws_t::jws_ps256, jws_t::jws_ps384, jws_t::jws_ps512,
        };
        for (unsigned int i = 0; i < RTL_NUMBER_OF(algs); i++) {
            do_key_match(&key, algs[i], crypto_use_t::use_sig);
        }
    }
    __finally2 {}
}

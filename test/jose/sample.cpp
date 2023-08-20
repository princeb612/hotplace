/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;

void dump_crypto_key (crypto_key_object_t* key, void*)
{
    uint32 nid = 0;

    nidof_evp_pkey (key->pkey, nid);
    printf ("nid %i kid %s alg %s use %i\n", nid, key->kid.c_str (), key->alg.c_str (), key->use);
}

void print_text (const char* text)
{
    console_color col;
    std::cout << col.set_style (console_style_t::bold).set_fgcolor (console_color_t::green).turnon () << text << col.turnoff () << std::endl;
}

void test_rfc7515_A1 ()
{
    print_text ("RFC 7515 A.1");

    const byte_t hs256_header[] = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file (&key, "rfc7515.jwk", 0);
    //key.for_each (dump_crypto_key, nullptr);

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
    rfc_result = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
                 "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc"
                 "GxlLmNvbS9pc19yb290Ijp0cnVlfQ."
                 "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    ret = jws.sign (&key, (char*) hs256_header, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    if (stricmp (rfc_result.c_str (), signature.c_str ())) {
        result = false;
    }
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS compact) - Verify");

    ret = jws.sign (&key, (char*) hs256_header, claim, signature, JOSE_FLATJSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, (char*) hs256_header, claim, signature, JOSE_JSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_HS ()
{
    print_text ("RFC 7515 A.1");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file (&key, "rfc7515.jwk", 0);
    //key.for_each (dump_crypto_key, nullptr);

    json_object_signing_encryption jose;
    std::string jws_result;

    jose_context_t* jose_context = nullptr;
    jose.open (&jose_context, &key);

    ret = jose.sign (jose_context, SIGN_HS256, claim, jws_result);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Sign");
    ret = jose.verify (jose_context, jws_result, result);
    std::cout << "JWS " << std::endl << jws_result.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Verify");

    ret = jose.sign (jose_context, SIGN_HS256, claim, jws_result, JOSE_FLATJSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Sign");
    ret = jose.verify (jose_context, jws_result, result);
    std::cout << "JWS " << std::endl << jws_result.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Verify");

    ret = jose.sign (jose_context, SIGN_HS256, claim, jws_result, JOSE_JSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS json) - Sign");
    ret = jose.verify (jose_context, jws_result, result);
    std::cout << "JWS " << std::endl << jws_result.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS json) - Verify");

    jose.close (jose_context);
}

void test_rfc7515_A2 ()
{
    print_text ("RFC 7515 A.2");

    /* RFC 7515 */
    const byte_t rs256_header[] = "{\"alg\":\"RS256\"}";
    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

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
    rfc_result = "eyJhbGciOiJSUzI1NiJ9."
                 "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
                 "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
                 "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
                 "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
                 "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
                 "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
                 "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
                 "p0igcN_IoypGlUPQGe77Rw";

    ret = jws.sign (&key, (char*) rs256_header, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    if (stricmp (rfc_result.c_str (), signature.c_str ())) {
        result = false;
    }
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS compact) - Verify");

    ret = jws.sign (&key, (char*) rs256_header, claim, signature, JOSE_FLATJSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, (char*) rs256_header, claim, signature, JOSE_JSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_A3 ()
{
    print_text ("RFC 7515 A.3");

    /* RFC 7515 */
    const byte_t es256_header[] = "{\"alg\":\"ES256\"}";
    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

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

    ret = jws.sign (&key, SIGN_ES256, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    // result changes
    // so test in https://jwt.io
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Verify");

    ret = jws.sign (&key, SIGN_ES256, claim, signature, JOSE_FLATJSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Verify");

    ret = jws.sign (&key, SIGN_ES256, claim, signature, JOSE_JSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON serialization) - Verify");

    std::string example = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    std::cout << "Example" << std::endl << example.c_str () << std::endl;
    ret = jws.verify (&key, example, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (Example)");
}

void test_rfc7515_A4 ()
{
    print_text ("RFC 7515 A.4");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

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

    //claimconst char payload[] = { 80, 97, 121, 108, 111, 97, 100, 0 };

    ret = jws.sign (&key, SIGN_ES512, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    // result changes
    // so test in https://jwt.io
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Verify");

    ret = jws.sign (&key, SIGN_ES512, claim, signature, JOSE_FLATJSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, SIGN_ES512, claim, signature, JOSE_JSON);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON serialization) - Verify");

    std::string example = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";
    std::cout << "Example" << std::endl << example.c_str () << std::endl;
    ret = jws.verify (&key, example, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (Example)");
}

void test_rfc7515_A5 ()
{
    print_text ("RFC 7515 A.5");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

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

    const char* unsecured_header = "{\"alg\":\"none\"}";

    ret = jws.sign (&key, unsecured_header, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Sign");

    // RFC sample - not support low security reason
    const char* sample = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    ret = jws.verify (&key, sample, result);
    std::cout << "compact" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Verify");
}

void test_rfc7515_A6 ()
{
    print_text ("RFC 7515 A.6");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    std::list <crypt_sig_t> headers;
    headers.push_back (SIGN_RS256);
    headers.push_back (SIGN_ES256);
    jws.sign (&key, headers, claim, signature, JOSE_JSON);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.6. Example JWS Using General JWS JSON Serialization");
}

void test_rfc7515_A7 ()
{
    print_text ("RFC 7515 A.7");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = ERROR_SUCCESS;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk", 0);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign (&key, SIGN_RS256, claim, signature, JOSE_FLATJSON);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;

    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.7. Example JWS Using Flattened JWS JSON Serialization");
}

int main ()
{
    test_rfc7515_A1 ();
    test_rfc7515_HS ();
    test_rfc7515_A2 ();
    test_rfc7515_A3 ();
    test_rfc7515_A4 ();
    test_rfc7515_A5 ();
    test_rfc7515_A6 ();
    test_rfc7515_A7 ();

    _test_case.report ();
    return _test_case.result ();
}

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

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
typedef struct _OPTION {
    bool dump_keys;

    _OPTION () : dump_keys (false)
    {
        // do nothing
    }
} OPTION;
t_shared_instance <cmdline_t<OPTION> > _cmdline;

void print_text (const char* text, ...)
{
    console_color concolor;
    va_list ap;

    va_start (ap, text);
    ansi_string string;
    string.vprintf (text, ap);
    va_end (ap);
    std::cout   << concolor.turnon ().set_style (console_style_t::bold).set_fgcolor (console_color_t::green)
                << string.c_str ()
                << std::endl;
    std::cout << concolor.turnoff ();
}

void test0 ()
{
    print_text ("basic informations");

    struct {
        const char* name;
        const EVP_CIPHER* evp;
    } table[] = {
        { "EVP_aes128_wrap", EVP_aes_128_wrap (), },
        { "EVP_aes192_wrap", EVP_aes_192_wrap (), },
        { "EVP_aes256_wrap", EVP_aes_256_wrap (), },
        { "EVP_aes128_gcm",  EVP_aes_128_gcm (),  },
        { "EVP_aes192_gcm",  EVP_aes_192_gcm (),  },
        { "EVP_aes256_gcm",  EVP_aes_256_gcm (),  },
        { "EVP_aes128_cbc",  EVP_aes_128_cbc (),  },
        { "EVP_aes192_cbc",  EVP_aes_192_cbc (),  },
        { "EVP_aes256_cbc",  EVP_aes_256_cbc (),  },
    };

    for (size_t i = 0; i < RTL_NUMBER_OF (table); i++) {
        int key_len = EVP_CIPHER_key_length (table[i].evp);
        int iv_len = EVP_CIPHER_iv_length (table[i].evp);

        std::cout << table[i].name << " key " << key_len << " iv " << iv_len << std::endl;
    }

#if __cplusplus >= 201103L    // c++11
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    std::function <void (const hint_jose_encryption_t*, void*)> lambda1 =
        [] (const hint_jose_encryption_t* item, void* user) -> void {
            printf ("    %s\n", item->alg_name);
        };
    std::function <void (const hint_signature_t*, void*)> lambda2 =
        [] (const hint_signature_t* item, void* user) -> void {
            printf ("    %s\n", item->jws_name);
        };

    printf ("JWA\n");
    advisor->jose_for_each_algorithm (lambda1, nullptr );

    printf ("JWE\n");
    advisor->jose_for_each_encryption (lambda1, nullptr );

    printf ("JWS\n");
    advisor->jose_for_each_signature (lambda2, nullptr );
#endif

    std::cout << "jwk test" << std::endl;

    json_web_key jwk;
    json_web_signature jws;

    crypto_key crypto_key_es521;
    jwk.load_file (&crypto_key_es521, "rfc7516_A4.jwk");

    EVP_PKEY* pkey = crypto_key_es521.any ();
    if (pkey) {
        basic_stream bs;
        dump_key (pkey, &bs);
        printf ("%s\n", bs.c_str ());
    }

    _test_case.assert (true, __FUNCTION__, "baseic informations");
}

void dump_crypto_key (crypto_key_object_t* key, void*)
{
    OPTION option = _cmdline->value (); // (*_cmdline).value () is ok

    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey (key->pkey, nid);
        printf ("nid %i kid %s alg %s use %i\n", nid, key->kid.c_str (), key->alg.c_str (), key->use);

        basic_stream bs;
        dump_key (key->pkey, &bs);
        printf ("%s\n", bs.c_str ());
    }
}

void test_rfc7515_A1 ()
{
    print_text ("RFC 7515 A.1");

    constexpr byte_t hs256_header[] = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

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

    ret = jws.sign (&key, (char*) hs256_header, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, (char*) hs256_header, claim, signature, jose_serialization_t::jose_json);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.1. Example JWS Using HMAC SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_HS ()
{
    print_text ("RFC 7515 A.1");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    bool result = false;

    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

    json_object_signing_encryption jose;
    std::string jws_result;

    jose_context_t* jose_context = nullptr;
    jose.open (&jose_context, &key);

    ret = jose.sign (jose_context, jws_t::jws_hs256, claim, jws_result);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Sign");
    ret = jose.verify (jose_context, jws_result, result);
    std::cout << "JWS " << std::endl << jws_result.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS compact) - Verify");

    ret = jose.sign (jose_context, jws_t::jws_hs256, claim, jws_result, jose_serialization_t::jose_flatjson);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Sign");
    ret = jose.verify (jose_context, jws_result, result);
    std::cout << "JWS " << std::endl << jws_result.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 JWS Using HMAC SHA-256 (JWS flat) - Verify");

    ret = jose.sign (jose_context, jws_t::jws_hs256, claim, jws_result, jose_serialization_t::jose_json);
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
    constexpr byte_t rs256_header[] = "{\"alg\":\"RS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

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

    ret = jws.sign (&key, (char*) rs256_header, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, (char*) rs256_header, claim, signature, jose_serialization_t::jose_json);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256 (JWS JSON serialization) - Verify");
}

void test_rfc7515_A3 ()
{
    print_text ("RFC 7515 A.3");

    /* RFC 7515 */
    constexpr byte_t es256_header[] = "{\"alg\":\"ES256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

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

    ret = jws.sign (&key, jws_t::jws_es256, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    // result changes
    // so test in https://jwt.io
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS compact) - Verify");

    ret = jws.sign (&key, jws_t::jws_es256, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.3. Example JWS Using ECDSA P-256 SHA-256 (JWS JSON flattended) - Verify");

    ret = jws.sign (&key, jws_t::jws_es256, claim, signature, jose_serialization_t::jose_json);
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

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

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

    ret = jws.sign (&key, jws_t::jws_es512, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    // result changes
    // so test in https://jwt.io
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS compact) - Verify");

    ret = jws.sign (&key, jws_t::jws_es512, claim, signature, jose_serialization_t::jose_flatjson);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Sign");
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.4. Example JWS Using ECDSA P-521 SHA-512 (JWS JSON flattened) - Verify");

    ret = jws.sign (&key, jws_t::jws_es512, claim, signature, jose_serialization_t::jose_json);
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

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

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

    ret = jws.sign (&key, unsecured_header, claim, signature);
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Sign");

    // RFC sample - not support low security reason
    constexpr char sample[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    ret = jws.verify (&key, sample, result);
    std::cout << "compact" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.5. Example Unsecured JWS (JWS compact) - Verify");
}

void test_rfc7515_A6 ()
{
    print_text ("RFC 7515 A.6");

    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    std::list <jws_t> headers;
    headers.push_back (jws_t::jws_rs256);
    headers.push_back (jws_t::jws_es256);
    jws.sign (&key, headers, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.6. Example JWS Using General JWS JSON Serialization");
}

void test_rfc7515_A7 ()
{
    print_text ("RFC 7515 A.7");

    const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign (&key, jws_t::jws_rs256, claim, signature, jose_serialization_t::jose_flatjson);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;

    _test_case.test (ret, __FUNCTION__, "RFC 7515 A.7. Example JWS Using Flattened JWS JSON Serialization");
}

void test_rfc7515_bypem ()
{
    print_text ("RFC 7515 by PEM");

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
    jwk.load_pem_file (&key, "rfc7515.pem", 0);
    jwk.write_pem_file (&key, "temp.pem", 0);

    json_web_signature jws;
    std::string signature;
    bool result = false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    jws.sign (&key, (char*) hs256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS HS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "HS256");
#endif

    jws.sign (&key, (char*) rs256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS256");

    jws.sign (&key, (char*) es256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS ES256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "ES256");

    jws.sign (&key, (char*) es512_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS ES512" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "ES512");

    jws.sign (&key, (char*) ps256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS PS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "PS256");
}

void test_rfc7515_bykeygen ()
{
    print_text ("RFC 7515 by key generation");

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

    key.generate (crypto_key_t::kty_hmac, 256, "sample");
    key.generate (crypto_key_t::kty_rsa, 2048, "sample");
    key.generate (crypto_key_t::kty_ec, 256, "sample");

    key.generate (crypto_key_t::kty_hmac, 256, "HS256");
    key.generate (crypto_key_t::kty_rsa, 2048, "RS256");
    key.generate (crypto_key_t::kty_rsa, 2048, "RS384");
    key.generate (crypto_key_t::kty_rsa, 2048, "RS512");
    key.generate (crypto_key_t::kty_ec, 256, "ES256");
    key.generate (crypto_key_t::kty_ec, 384, "ES384");
    key.generate (crypto_key_t::kty_ec, 521, "ES512");

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign (&key, (char*) hs256_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS HS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "HS256");

    jws.sign (&key, (char*) rs256_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS256");

    jws.sign (&key, (char*) rs384_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS384" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS384");

    jws.sign (&key, (char*) rs512_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS512" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS512");

    jws.sign (&key, (char*) es256_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS ES256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "ES256");

    jws.sign (&key, (char*) ps256_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS PS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "PS256");

    jws.sign (&key, (char*) rs384_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS384" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS384");

    jws.sign (&key, (char*) es384_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS ES384" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "ES384");

    jws.sign (&key, (char*) ps384_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS PS384" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "PS384");

    jws.sign (&key, (char*) rs512_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS RS512" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RS512");

    jws.sign (&key, (char*) es512_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS ES512" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "ES512");

    jws.sign (&key, (char*) ps512_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS PS512" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "PS512");

    std::list<std::string> headers;
    headers.push_back ((char*) hs256_header);
    headers.push_back ((char*) rs256_header);
    headers.push_back ((char*) es256_header);
    headers.push_back ((char*) ps256_header);
    jws.sign (&key, headers, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS HS256,RS256,ES256,PS256" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "HS256");
}

return_t test_jose_file (crypto_key* key, const char* file, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        result = false;

        if (nullptr == key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open (file);
        if (errorcode_t::success == ret) {
            fs.begin_mmap ();

            json_object_signing_encryption jose;
            jose_context_t* jose_context = nullptr;
            binary_t source;

            jose.open (&jose_context, key);
            ret = jose.decrypt (jose_context, std::string ((char *) fs.data (), fs.size ()), source, result);
            jose.close (jose_context);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

void test_rfc7516_A1_test ()
{
    print_text ("RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM");

    // A.1.1.  JOSE Header
    std::string jose_header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
    // eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
    // A.1.2.  Content Encryption Key (CEK)
    constexpr byte_t cek [] =
    { 177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
      212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
      234, 64, 252 };
    // A.1.3.  Key Encryption
    // see rfc7516_A1.jwk
    constexpr byte_t encrypted_key [] =
    { 56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
      22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
      82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
      145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
      74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
      13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
      173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
      89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
      243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
      41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
      215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
      63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
      193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
      206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
      104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
      89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
      172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
      117, 114, 135, 206 };
    // OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
    // ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
    // Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
    // mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
    // 1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
    // 6UklfCpIMfIjf7iGdXKHzg

    // A.1.4.  Initialization Vector
    byte_t iv [] =
    { 227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219 };
    // 48V1_ALb6US04U3b

    // A.1.5.  Additional Authenticated Data
    byte_t aad [] =
    { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
      116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
      54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81 };
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    // see A.1.1

    // A.1.6.  Content Encryption
    byte_t ciphertext [] =
    { 229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
      233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
      104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
      123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
      160, 109, 64, 63, 192 };
    // 5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
    // SdiwkIr3ajwQzaBtQD_A
    byte_t tag [] =
    { 92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
      210, 145 };
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
    EVP_PKEY* pkey;
    std::string kid;
    std::string jose_header_encoded;
    std::string encrypted_key_encoded;
    std::string iv_encoded;
    std::string ciphertext_encoded;
    std::string tag_encoded;
    //binary_t aad_decoded;
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    binary_t data;

    jwk.load_file (&key, "rfc7516_A1.jwk");
    key.for_each (dump_crypto_key, nullptr);

    dump_memory ((byte_t*) input.c_str (), input.size (), &bs);
    printf ("input\n%s\n", bs.c_str ());
    dump_memory ((byte_t*) jose_header.c_str (), jose_header.size (), &bs);
    printf ("jose_header\n%s\n", bs.c_str ());
    dump_memory (cek, RTL_NUMBER_OF (cek), &bs);
    printf ("cek\n%s\n", bs.c_str ());
    dump_memory (encrypted_key, RTL_NUMBER_OF (encrypted_key), &bs);
    printf ("encrypted_key\n%s\n", bs.c_str ());
    dump_memory (iv, RTL_NUMBER_OF (iv), &bs);
    printf ("iv\n%s\n", bs.c_str ());
    dump_memory (aad, RTL_NUMBER_OF (aad), &bs);
    printf ("aad\n%s\n", bs.c_str ());
    dump_memory (ciphertext, RTL_NUMBER_OF (ciphertext), &bs);
    printf ("ciphertext\n%s\n", bs.c_str ());
    dump_memory (tag, RTL_NUMBER_OF (tag), &bs);
    printf ("tag\n%s\n", bs.c_str ());

    // A.1.1
    jose_header_encoded = base64_encode ((byte_t*) jose_header.c_str (), jose_header.size (), base64_encoding_t::base64url_encoding);
    printf ("jose_header_encoded\n%s\n", jose_header_encoded.c_str ());
    // A.1.3
    encrypted_key_encoded = base64_encode (encrypted_key, RTL_NUMBER_OF (encrypted_key), base64_encoding_t::base64url_encoding);
    printf ("encrypted_key_encoded\n%s\n", encrypted_key_encoded.c_str ());

    encrypted_key_data.insert (encrypted_key_data.end (), encrypted_key, encrypted_key + RTL_NUMBER_OF (encrypted_key));
    pkey = key.select (kid, crypto_use_t::use_enc);
    json_object_signing_encryption jose;
    crypt.decrypt (pkey, encrypted_key_data, decrypted_key_data, crypt_enc_t::rsa_oaep);
    dump_memory (&decrypted_key_data[0], decrypted_key_data.size (), &bs);
    printf ("decrypted_key\n%s\n", bs.c_str ());

    if ((decrypted_key_data.size () == RTL_NUMBER_OF (cek)) && (0 == memcmp (&decrypted_key_data[0], cek, RTL_NUMBER_OF (cek)))) {
        printf ("cek match\n");
        result = true;
    } else {
        printf ("cek mismatch\n");
        result = false;
    }
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                     "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.3)");

    // A.1.4
    iv_encoded = base64_encode (iv, RTL_NUMBER_OF (iv), base64_encoding_t::base64url_encoding);
    printf ("iv_encoded\n%s\n", iv_encoded.c_str ());
    // A.1.5
    aad_data.insert (aad_data.end (), aad, aad + RTL_NUMBER_OF (aad));
    if ((jose_header_encoded.size () == RTL_NUMBER_OF (aad)) && (0 == memcmp (jose_header_encoded.c_str (), aad, RTL_NUMBER_OF (aad)))) {
        printf ("aad match\n");
        result = true;
    } else {
        printf ("aad mismatch\n");
        result = false;
    }
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                     "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.5)");
    // A.1.6

    tag_data.insert (tag_data.end (), tag, tag + RTL_NUMBER_OF (tag));
    crypt.open (&crypt_handle, crypt_algorithm_t::aes256, crypt_mode_t::gcm, cek, RTL_NUMBER_OF (cek), iv, RTL_NUMBER_OF (iv));
    // tag from plain, aad
    crypt.encrypt2 (crypt_handle, (byte_t*) input.c_str (), input.size (), data, &aad_data, &tag_gen);
    dump_memory (&data[0], data.size (), &bs);
    printf ("data\n%s\n", bs.c_str ());
    dump_memory (&tag_gen[0], tag_gen.size (), &bs);
    printf ("tag_gen\n%s\n", bs.c_str ());
    if ((tag_gen.size () == RTL_NUMBER_OF (tag)) && (0 == memcmp (&tag_gen[0], tag, RTL_NUMBER_OF (tag)))) {
        printf ("tag match\n");
        result = true;
    } else {
        printf ("tag mismatch\n");
        result = false;
    }
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                     "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.6, tag)");
    if ((data.size () == RTL_NUMBER_OF (ciphertext)) && (0 == memcmp (&data[0], ciphertext, RTL_NUMBER_OF (ciphertext)))) {
        printf ("ciphertext match\n");
        result = true;
    } else {
        printf ("ciphertext mismatch\n");
        result = false;
    }
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                     "RFC 7516 Appendix A - A.1.  Example JWE using RSAES-OAEP and AES GCM (A.1.6, ciphertext)");

    // plain from ciphertext, aad, tag
    crypt.decrypt2 (crypt_handle, ciphertext, RTL_NUMBER_OF (ciphertext), plain, &aad_data, &tag_data);
    dump_memory (&plain[0], plain.size (), &bs);
    printf ("plain\n%s\n", bs.c_str ());

    ciphertext_encoded = base64_encode (&data[0], data.size (), base64_encoding_t::base64url_encoding);
    printf ("ciphertext_encoded\n%s\n", ciphertext_encoded.c_str ());
    tag_encoded = base64_encode (&tag_gen[0], tag_gen.size (), base64_encoding_t::base64url_encoding);
    printf ("tag_encoded\n%s\n", tag_encoded.c_str ());

    crypt.close (crypt_handle);

    // A.1.7
    printf ("header\n%s.\n", jose_header_encoded.c_str ());
    printf ("key\n%s.\n", encrypted_key_encoded.c_str ());
    printf ("iv\n%s.\n", iv_encoded.c_str ());
    printf ("ciphertext\n%s.\n", ciphertext_encoded.c_str ());
    printf ("tag\n%s\n", tag_encoded.c_str ());
}

void test_rfc7516_A1 ()
{
    //return_t ret = errorcode_t::success;

    print_text ("RFC 7516 A.1");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7516_A1.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::string jose_header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open (&context, &key);

    jose.encrypt (context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, convert (input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, compact, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (compact)");

    jose.encrypt (context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, convert (input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt (context, json_flat, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (flat)");

    jose.encrypt (context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep, convert (input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt (context, json_serial, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (json)");

    jose.close (context);

    std::cout << "RFC 7516 A.1. compact" << std::endl << compact.c_str () << std::endl;
    std::cout << "RFC 7516 A.1. flattened JSON serialization" << std::endl << json_flat.c_str () << std::endl;
    std::cout << "RFC 7516 A.1. JSON serialization" << std::endl << json_serial.c_str () << std::endl;

    ret = test_jose_file (&key, "rfc7516_A1.jws", result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.1. JWE using RSAES-OAEP and AES GCM (file)");
}

void test_rsa_oaep ()
{
    print_text ("RFC 7516 A.1 RSA-OAEP");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file (&key, "rfc7516_A1.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::string input = "The true sign of intelligence is not knowledge but imagination.";

    jose.open (&context, &key);
    jose.encrypt (context, jwe_t::jwe_a128gcm, jwa_t::jwa_rsa_oaep, convert (input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, output, plain, result);
    jose.close (context);

    std::cout << output.c_str () << std::endl;

    _test_case.test (ret, __FUNCTION__, "RSA-OAEP");
}

void test_rsa_oaep_256 ()
{
    print_text ("RFC 7516 A.1 RSA-OAEP-256");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file (&key, "rfc7516_A1.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::string jose_header = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}";
    std::string input = "The true sign of intelligence is not knowledge but imagination.";

    jose.open (&context, &key);
    jose.encrypt (context, jwe_t::jwe_a256gcm, jwa_t::jwa_rsa_oaep_256, convert (input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, output, plain, result);
    jose.close (context);

    std::cout << output.c_str () << std::endl;

    _test_case.test (ret, __FUNCTION__, "RSA-OAEP-256");
}

void test_rfc7516_A2 ()
{
    //return_t ret = errorcode_t::success;

    print_text ("RFC 7516 A.2");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7516_A2.jwk");
    key.for_each (dump_crypto_key, nullptr);

    //std::string jose_header = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}";
    std::string input = "Live long and prosper.";
    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open (&context, &key);

    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, convert (input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, compact, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (compact)");

    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, convert (input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt (context, compact, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (flat)");

    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_rsa_1_5, convert (input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt (context, compact, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (json)");

    jose.close (context);

    std::cout << "RFC 7516 A.2. compact" << std::endl << compact.c_str () << std::endl;
    std::cout << "RFC 7516 A.2. flattened JSON serialization" << std::endl << json_flat.c_str () << std::endl;
    std::cout << "RFC 7516 A.2. JSON serialization" << std::endl << json_serial.c_str () << std::endl;

    ret = test_jose_file (&key, "rfc7516_A2.jws", result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.2. JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 (file)");
}

void test_rfc7516_A3 ()
{
    print_text ("RFC 7516 A.3");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7516_A3.jwk");
    key.for_each (dump_crypto_key, nullptr);

    //std::string jose_header = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
    std::string input = "Live long and prosper.";

    std::string compact;
    std::string json_flat;
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open (&context, &key);
    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, convert (input), compact, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, compact, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (compact)");
    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, convert (input), json_flat, jose_serialization_t::jose_flatjson);
    ret = jose.decrypt (context, json_flat, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (flat)");
    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_a128kw, convert (input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt (context, json_serial, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (json)");
    jose.close (context);

    std::cout << "RFC 7516 A.3. compact" << std::endl << compact.c_str () << std::endl;
    std::cout << "RFC 7516 A.3. flattened JSON serialization" << std::endl << json_flat.c_str () << std::endl;
    std::cout << "RFC 7516 A.3. JSON serialization" << std::endl << json_serial.c_str () << std::endl;

    ret = test_jose_file (&key, "rfc7516_A3.jws", result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.3. JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (file)");
}

void test_rfc7516_A4 ()
{
    //return_t ret = errorcode_t::success;

    print_text ("RFC 7516 A.4");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7516_A4.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::string input = "Live long and prosper.";
    std::string json_serial;
    binary_t source;
    bool result = false;

    jose_context_t* context = nullptr;
    jose.open (&context, &key);
    std::list <jwa_t> algs;
    //algs.push_back (jwa_t::jwa_rsa_1_5);
    //algs.push_back (jwa_t::jwa_a128kw);
    algs.push_back (jwa_t::jwa_pbes2_hs256_a128kw);
    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, algs, convert (input), json_serial, jose_serialization_t::jose_json);
    ret = jose.decrypt (context, json_serial, source, result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.4. JWE Using General JWE JSON Serialization (json)");
    jose.close (context);

    printf ("%s\n", json_serial.c_str ());

    ret = test_jose_file (&key, "rfc7516_A4.jws", result);
    _test_case.test (ret, __FUNCTION__, "RFC 7516 A.4. JWE Using General JWE JSON Serialization (file)");
}

void test_rfc7516_B ()
{
    return_t ret = errorcode_t::success;

    print_text ("RFC 7516 B Example AES_128_CBC_HMAC_SHA_256 Computation");

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
    constexpr byte_t key [] =
    { 4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
      206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
      44, 207 };
    // B.2.  Encrypt Plaintext to Create Ciphertext
    constexpr byte_t plain [] =
    { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
      112, 114, 111, 115, 112, 101, 114, 46 };
    constexpr byte_t encrypted_data [] =
    { 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
      75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
      112, 56, 102 };
    // B.3.  64-Bit Big-Endian Representation of AAD Length
    constexpr byte_t aad [] =
    { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
      83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
      77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
      110, 48 };
    constexpr byte_t concat_sample [] =
    { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
      83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
      77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
      110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
      116, 104, 101, 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24,
      152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215,
      104, 143, 112, 56, 102, 0, 0, 0, 0, 0, 0, 1, 152 };
    uint64 al = hton64 (RTL_NUMBER_OF (aad) * 8);
    // B.4.  Initialization Vector Value
    constexpr byte_t iv [] =
    { 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
      101 };
    // B.5.  Create Input to HMAC Computation
    // B.6.  Compute HMAC Value
    // B.7.  Truncate HMAC Value to Create Authentication Tag
    constexpr byte_t tag [] =
    { 83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
      194, 85 };

    // compute
    __try2
    {
        dump_memory (key, RTL_NUMBER_OF (key), &bs);
        printf ("key\n%s\n", bs.c_str ());

        dump_memory (plain, RTL_NUMBER_OF (plain), &bs);
        printf ("plain\n%s\n", bs.c_str ());

        dump_memory (iv, RTL_NUMBER_OF (iv), &bs);
        printf ("iv\n%s\n", bs.c_str ());

        // B.2
        crypt.open (&crypt_handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, key + 16, 16, iv, 16);
        crypt.encrypt (crypt_handle, plain, RTL_NUMBER_OF (plain), enc_value);
        dump_memory (&enc_value [0], enc_value.size (), &bs);
        printf ("encryption result (computed)\n%s\n", bs.c_str ());
        // if (encryption result = encrypted_data) then success
        // test vice versa now
        dump_memory (encrypted_data, RTL_NUMBER_OF (encrypted_data), &bs);
        printf ("encryption result (rfc sample)\n%.*s\n", (int) bs.size (), bs.c_str ());
        crypt.decrypt (crypt_handle, encrypted_data, RTL_NUMBER_OF (encrypted_data), test);
        printf ("decrypted result size %zi\n", test.size ());
        dump_memory (&test [0], test.size (), &bs);
        printf ("decrypt the encryption result (rfc sample)\n%.*s\n", (int) bs.size (), bs.c_str ());
        // B.5
        binary_t concat; // concatenate AAD, IV, CT, AL
        concat.insert (concat.end (), aad, aad + RTL_NUMBER_OF (aad));
        concat.insert (concat.end (), iv, iv + RTL_NUMBER_OF (iv));
        concat.insert (concat.end (), enc_value.begin (), enc_value.end ());
        concat.insert (concat.end (), (byte_t*) &al, (byte_t*) &al + sizeof (int64));
        dump_memory (&concat[0], concat.size (), &bs);
        printf ("concat\n%s\n", bs.c_str ());
        dump_memory (concat_sample, RTL_NUMBER_OF (concat_sample), &bs);
        printf ("concat (rfc sample)\n%s\n", bs.c_str ());
        // B.6
        hash.open (&hash_handle, hash_algorithm_t::sha2_256, key, 16);
        hash.hash (hash_handle, &concat[0], concat.size (), hmac_value);

        dump_memory (&hmac_value[0], hmac_value.size (), &bs);
        printf ("hmac_value\n%s\n", bs.c_str ());

        constexpr byte_t hmac_sample [] =
        { 83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
          194, 85, 9, 84, 229, 201, 219, 135, 44, 252, 145, 102, 179, 140, 105,
          86, 229, 116 };
        dump_memory (hmac_sample, RTL_NUMBER_OF (hmac_sample), &bs);
        printf ("hmac (rfc sample)\n%s\n", bs.c_str ());

        // B.7
        binary_t trunc;
        trunc.insert (trunc.end (), &hmac_value[0], &hmac_value[0] + 16);
        dump_memory (&trunc[0], trunc.size (), &bs);
        printf ("trunc\n%s\n", bs.c_str ());

        if ((RTL_NUMBER_OF (tag) == trunc.size ()) && (0 == memcmp (&trunc[0], tag, trunc.size ()))) {
            // do nothing
        } else {
            ret = errorcode_t::internal_error;
        }
        _test_case.test (ret, __FUNCTION__,
                         "RFC 7516 B.  Example AES_128_CBC_HMAC_SHA_256 Computation");
    }
    __finally2
    {
        crypt.close (crypt_handle);
        hash.close (hash_handle);
    }
}

void test_jwk ()
{
    print_text ("RFC 7517");
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    binary_t buffer;
    size_t buflen = 0;

    jwk.load_file (&key, "rfc7520_priv.jwk");
    key.for_each (dump_crypto_key, nullptr);

    jwk.write (&key, nullptr, &buflen, 0);
    buffer.resize (buflen);
    jwk.write (&key, (char*) &buffer[0], &buflen, 0);

    std::cout
        << "public key"
        << std::endl
        << (char*) &buffer[0]
        << std::endl;

    jwk.write (&key, nullptr, &buflen, 1);
    buffer.resize (buflen);
    jwk.write (&key, (char*) &buffer[0], &buflen, 1);

    std::cout
        << "private key"
        << std::endl
        << (char*) &buffer[0]
        << std::endl;

    // RFC 7520 "kid": "bilbo.baggins@hobbiton.example"
    // x org AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt
    //       0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad
    // x bug cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0
    //         72992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad
    std::string x1 = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
    std::string x2 = "cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0";
    binary_t b1, b2;
    base64_decode (x1.c_str (), x1.size (), b1, base64_encoding_t::base64url_encoding);
    base64_decode (x2.c_str (), x2.size (), b2, base64_encoding_t::base64url_encoding);
    std::cout
        << "what's different ?"
        << std::endl
        << "x1 : "
        << x1.c_str ()
        << std::endl
        << "     "
        << base16_encode (b1).c_str ()
        << std::endl
        << "x2 : "
        << x2.c_str ()
        << std::endl
        << "     "
        << base16_encode (b2).c_str ()
        << std::endl;
}

void test_rfc7517_C ()
{
    print_text ("RFC 7517 C");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    crypto_keychain keygen;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file (&key, "rfc7517_C.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    constexpr char passphrase[] = "Thus from my lips, by yours, my sin is purged.";
    keygen.add_oct (&key, nullptr, jwa_t::jwa_pbes2_hs256_a128kw, (byte_t*) passphrase, strlen (passphrase), crypto_use_t::use_enc);

    jose.open (&context, &key);
    jose.encrypt (context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_pbes2_hs256_a128kw, convert (input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt (context, output, plain, result);
    jose.close (context);

    printf ("%.*s\n", (int) output.size (), (char*) &output[0]);
    _test_case.test (ret, __FUNCTION__, "RFC 7517 Appendix C. Encrypted RSA Private Key");
}

void test_rfc7518_RSASSA_PSS ()
{
    print_text ("RFC 7518 3.5");
    constexpr byte_t ps256_header[] = "{\"alg\":\"PS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file (&key, "rfc7515.jwk");
    key.for_each (dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign (&key, (char*) ps256_header, claim, signature);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS compact" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS compact)");

    jws.sign (&key, (char*) ps256_header, claim, signature, jose_serialization_t::jose_flatjson);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON flattened" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS JSON flattened)");

    jws.sign (&key, (char*) ps256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify (&key, signature, result);
    std::cout << "JWS JSON serialization" << std::endl << signature.c_str () << std::endl;
    _test_case.test (ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS JSON serialization)");
}

int test_ecdh ()
{
    crypto_key keys;
    crypto_keychain keyset;

    binary_t x_alice;
    binary_t y_alice;
    binary_t d_alice;
    binary_t x_bob;
    binary_t y_bob;
    binary_t d_bob;
    binary_t secret_alice;
    binary_t secret_bob;

    keyset.add_ec (&keys, "alice", NID_secp384r1);
    keyset.add_ec (&keys, "bob", NID_secp384r1);

    EVP_PKEY* alicePrivateKey = (EVP_PKEY*) keys.find ("alice", crypto_key_t::kty_ec);
    EVP_PKEY* bobPrivateKey = (EVP_PKEY*) keys.find ("bob", crypto_key_t::kty_ec);

    EVP_PKEY* alicePublicKey = (EVP_PKEY*) get_peer_key (alicePrivateKey);
    EVP_PKEY* bobPublicKey = (EVP_PKEY*) get_peer_key (bobPrivateKey);

    keys.get_public_key (alicePrivateKey, x_alice, y_alice);
    keys.get_private_key (alicePrivateKey, d_alice);
    keys.get_public_key (bobPrivateKey, x_bob, y_bob);
    keys.get_private_key (bobPrivateKey, d_bob);

    dh_key_agreement (alicePrivateKey, bobPublicKey, secret_alice);
    dh_key_agreement (bobPrivateKey, alicePublicKey, secret_bob);

    EVP_PKEY_free (alicePublicKey);
    EVP_PKEY_free (bobPublicKey);

    std::cout
        << "alice public key  x : "
        << base16_encode (x_alice).c_str ()
        << std::endl
        << "alice public key  y : "
        << base16_encode (y_alice).c_str ()
        << std::endl
        << "alice private key d : "
        << base16_encode (d_alice).c_str ()
        << std::endl
        << "bob   public key  x : "
        << base16_encode (x_bob).c_str ()
        << std::endl
        << "bob   public key  y : "
        << base16_encode (y_bob).c_str ()
        << std::endl
        << "bob   private key d : "
        << base16_encode (d_bob).c_str ()
        << std::endl

        << "secret computed by alice : "
        << base16_encode (secret_alice).c_str ()
        << std::endl
        << "secret computed by bob   : "
        << base16_encode (secret_bob).c_str ()

        << std::endl;

    bool result = (secret_alice == secret_bob);
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__, "ECDH");
    return 0;
}

void test_rfc7518_C ()
{
    print_text ("RFC 7518 Appendix C.  Example ECDH-ES Key Agreement Computation");

    json_web_key jwk;
    basic_stream bs;
    crypto_key key_alice;
    crypto_key key_bob;

    jwk.load_file (&key_alice, "rfc7518_C_alice.jwk");
    jwk.load_file (&key_bob, "rfc7518_C_bob.jwk");

    key_alice.for_each (dump_crypto_key, nullptr);
    key_bob.for_each (dump_crypto_key, nullptr);

    EVP_PKEY* pkey_alice = key_alice.select (crypto_use_t::use_enc);
    EVP_PKEY* pkey_bob = key_bob.select (crypto_use_t::use_enc);

    binary_t secret_bob;
    dh_key_agreement (pkey_bob, pkey_alice, secret_bob);

    std::cout
        << "Z (ECDH-ES key agreement output) : "
        << std::endl
        << base16_encode (secret_bob).c_str ()
        << std::endl;
#if __cplusplus >= 201103L    // c++11
    for_each (secret_bob.begin (), secret_bob.end (), [] (byte_t c) {
        printf ("%i,", c);
    });
#else
    for (binary_t::iterator iter = secret_bob.begin (); iter != secret_bob.end (); iter++) {
        byte_t c = *iter;
        printf ("%i,", c);
    }
#endif
    std::cout << std::endl;

    // apu Alice
    // apv Bob
    constexpr char alg[] = "A128GCM";
    constexpr char apu[] = "Alice";
    constexpr char apv[] = "Bob";
    binary_t otherinfo;

    compose_otherinfo (alg, apu, apv, 16 << 3, otherinfo);

    dump_memory (&otherinfo[0], otherinfo.size (), &bs);
    std::cout << "otherinfo" << std::endl << bs.c_str () << std::endl;
    std::cout << "[";
#if __cplusplus >= 201103L    // c++11
    for_each (otherinfo.begin (), otherinfo.end (), [] (byte_t c) {
        printf ("%i,", c);
    });
#else
    for (binary_t::iterator iter = otherinfo.begin (); iter != otherinfo.end (); iter++) {
        byte_t c = *iter;
        printf ("%i,", c);
    }
#endif
    std::cout << "]" << std::endl;

    binary_t derived;
    concat_kdf (secret_bob, otherinfo, 16, derived);

    dump_memory (&derived[0], derived.size (), &bs);
    std::cout << "derived" << std::endl << bs.c_str () << std::endl;
    std::cout << "[";
#if __cplusplus >= 201103L    // c++11
    for_each (derived.begin (), derived.end (), [] (byte_t c) {
        printf ("%i,", c);
    });
#else
    for (binary_t::iterator iter = derived.begin (); iter != derived.end (); iter++) {
        byte_t c = *iter;
        printf ("%i,", c);
    }
#endif
    std::cout << "]" << std::endl;

    std::string sample = "VqqN6vgjbSBcIijNcacQGg";
    std::string computation = base64_encode (derived, base64_encoding_t::base64url_encoding);
    std::cout << computation.c_str () << std::endl;

    bool result = (sample == computation);
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__, "RFC 7518 Appendix C.  Example ECDH-ES Key Agreement Computation");

    ecdh_es (pkey_bob, pkey_alice, alg, apu, apv, 16, derived);
    dump_memory (&derived[0], derived.size (), &bs);
    std::cout << "derived" << std::endl << bs.c_str () << std::endl;
    std::cout << "[";
#if __cplusplus >= 201103L    // c++11
    for_each (derived.begin (), derived.end (), [] (byte_t c) {
        printf ("%i,", c);
    });
#else
    for (binary_t::iterator iter = derived.begin (); iter != derived.end (); iter++) {
        byte_t c = *iter;
        printf ("%i,", c);
    }
#endif
    std::cout << "]" << std::endl;
}

return_t test_rfc7520_signature (crypto_key *key, const char* filename, const char* testcase_name)
{
    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    file_stream fs;
    return_t ret = errorcode_t::success;
    bool result = false;

    ret = fs.open (filename);
    if (errorcode_t::success == ret) {
        fs.begin_mmap ();

        byte_t* data = fs.data ();
        size_t datasize = fs.size ();
        if (data) {
            ret = jws.verify (key, std::string ((char*) data, datasize), result);
        }
        fs.end_mmap ();
        fs.close ();
    }
    _test_case.test (ret, __FUNCTION__, testcase_name);
    return ret;
}

return_t test_rfc7520_jwe (crypto_key *key, const char* filename, const char* testcase_name)
{
    printf ("%s\n", testcase_name);
    json_object_signing_encryption jose;
    jose_context_t* handle = nullptr;
    file_stream fs;
    basic_stream bs;
    return_t ret = errorcode_t::success;
    bool result = false;
    binary_t output;

    ret = fs.open (filename);
    if (errorcode_t::success == ret) {
        fs.begin_mmap ();

        byte_t* data = fs.data ();
        size_t datasize = fs.size ();
        if (data) {
            jose.open (&handle, key);
            ret = jose.decrypt (handle, std::string ((char*) data, datasize), output, result);
            if (errorcode_t::success == ret) {
                printf ("%.*s\n", (int) datasize, data);
                dump_memory (&output[0], output.size (), &bs);
                printf ("%s\n", bs.c_str ());
            }
            jose.close (handle);
        }
        fs.end_mmap ();
        fs.close ();
    }
    _test_case.test (ret, __FUNCTION__, testcase_name);
    return ret;
}

void test_rfc7520 ()
{
    print_text ("RFC 7520");
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7520_priv.jwk");
    key.for_each (dump_crypto_key, nullptr);

    // 4.1 "RS256"
    test_rfc7520_signature (&key, "rfc7520_figure13.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 13)");
    test_rfc7520_signature (&key, "rfc7520_figure14.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 14)");
    test_rfc7520_signature (&key, "rfc7520_figure15.jws", "RFC 7520 4.1.  RSA v1.5 Signature (figure 15)");

    // 4.2 "PS256"
    test_rfc7520_signature (&key, "rfc7520_figure20.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 20)");
    test_rfc7520_signature (&key, "rfc7520_figure21.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 21)");
    test_rfc7520_signature (&key, "rfc7520_figure22.jws", "RFC 7520 4.2.  RSA-PSS Signature (figure 22)");

    // 4.3 "ES256"
    test_rfc7520_signature (&key, "rfc7520_figure27.jws", "RFC 7520 4.3.  ECDSA Signature (figure 27)");
    test_rfc7520_signature (&key, "rfc7520_figure28.jws", "RFC 7520 4.3.  ECDSA Signature (figure 28)");
    test_rfc7520_signature (&key, "rfc7520_figure29.jws", "RFC 7520 4.3.  ECDSA Signature (figure 29)");

    // 4.4 "HS256"
    test_rfc7520_signature (&key, "rfc7520_figure34.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 34)");
    test_rfc7520_signature (&key, "rfc7520_figure35.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 35)");
    test_rfc7520_signature (&key, "rfc7520_figure36.jws", "RFC 7520 4.4.  HMAC-SHA2 Integrity Protection (figure 36)");

    // 4.5.  Signature with Detached Content
    // 4.6.  Protecting Specific Header Fields
    test_rfc7520_signature (&key, "rfc7520_figure49.jws", "RFC 7520 4.6.  Protecting Specific Header Fields (figure 49)");
    test_rfc7520_signature (&key, "rfc7520_figure50.jws", "RFC 7520 4.6.  Protecting Specific Header Fields (figure 50)");

    // 4.7.  Protecting Content Only
    test_rfc7520_signature (&key, "rfc7520_figure54.jws", "RFC 7520 4.7.  Protecting Content Only (figure 54)");
    test_rfc7520_signature (&key, "rfc7520_figure55.jws", "RFC 7520 4.7.  Protecting Content Only (figure 55)");

    // 4.8.  Multiple Signatures
    test_rfc7520_signature (&key, "rfc7520_figure61.jws", "RFC 7520 4.8.  Multiple Signatures #1 (figure 61)");
    test_rfc7520_signature (&key, "rfc7520_figure65.jws", "RFC 7520 4.8.  Multiple Signatures #2 (figure 65)");
    test_rfc7520_signature (&key, "rfc7520_figure70.jws", "RFC 7520 4.8.  Multiple Signatures #3 (figure 70)");
    test_rfc7520_signature (&key, "rfc7520_figure71.jws", "RFC 7520 4.8.  Multiple Signatures (figure 71)");

    // 5.1 "RSA1_5" "A128CBC-HS256"
    test_rfc7520_jwe (&key, "rfc7520_figure81.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 81)");
    test_rfc7520_jwe (&key, "rfc7520_figure82.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 82)");
    test_rfc7520_jwe (&key, "rfc7520_figure83.jwe", "RFC 7520 5.1.  Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 (figure 83)");
    // 5.2 "RSA-OAEP" "A256GCM"
    test_rfc7520_jwe (&key, "rfc7520_figure92.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 92)");
    test_rfc7520_jwe (&key, "rfc7520_figure93.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 93)");
    test_rfc7520_jwe (&key, "rfc7520_figure94.jwe", "RFC 7520 5.2.  Key Encryption Using RSA-OAEP with AES-GCM (figure 94)");
    // 5.3 "PBES2-HS512+A256KW" "A128CBC-HS256"
    crypto_key crypto_key2;
    crypto_keychain keygen;
    binary_t password_figure96;
    // entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun
    const char* figure96 = "entrap_o\xe2\x80\x93" "peter_long\xe2\x80\x93" "credit_tun";
    keygen.add_oct (&crypto_key2, nullptr, jwa_t::jwa_pbes2_hs512_a256kw, (byte_t*) figure96, strlen (figure96), crypto_use_t::use_enc);
    test_rfc7520_jwe (&crypto_key2, "rfc7520_figure105.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 105)");
    test_rfc7520_jwe (&crypto_key2, "rfc7520_figure106.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 106)");
    test_rfc7520_jwe (&crypto_key2, "rfc7520_figure107.jwe", "RFC 7520 5.3.  Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2 (figure 107)");
    // 5.4 "ECDH-ES+A128KW" "A256GCM"
    test_rfc7520_jwe (&key, "rfc7520_figure117.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 117)");
    test_rfc7520_jwe (&key, "rfc7520_figure118.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 118)");
    test_rfc7520_jwe (&key, "rfc7520_figure119.jwe", "RFC 7520 5.4.  Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM  (figure 119)");
    // 5.5 "ECDH-ES" "A128CBC-HS256"
    test_rfc7520_jwe (&key, "rfc7520_figure128.jwe", "RFC 7520 5.5.  Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2 (figure 128)");
    test_rfc7520_jwe (&key, "rfc7520_figure129.jwe", "RFC 7520 5.5.  Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2 (figure 129)");
    // 5.6 "dir" "A256GCM"
    test_rfc7520_jwe (&key, "rfc7520_figure136.jwe", "RFC 7520 5.6.  Direct Encryption Using AES-GCM (figure 136)");
    test_rfc7520_jwe (&key, "rfc7520_figure137.jwe", "RFC 7520 5.6.  Direct Encryption Using AES-GCM (figure 137)");
    // 5.7 "A256GCMKW" "A128CBC-HS256"
    test_rfc7520_jwe (&key, "rfc7520_figure148.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 148)");
    test_rfc7520_jwe (&key, "rfc7520_figure149.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 149)");
    test_rfc7520_jwe (&key, "rfc7520_figure150.jwe", "RFC 7520 5.7.  Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2 (figure 150)");
    // 5.8 "A128KW" "A256GCM"
    test_rfc7520_jwe (&key, "rfc7520_figure159.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 159)");
    test_rfc7520_jwe (&key, "rfc7520_figure160.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 160)");
    test_rfc7520_jwe (&key, "rfc7520_figure161.jwe", "RFC 7520 5.8.  Key Wrap Using AES-KeyWrap with AES-GCM (figure 161)");

    // 5.9 Compressed Content
    test_rfc7520_jwe (&key, "rfc7520_figure170.jwe", "RFC 7520 5.9.  Compressed Content (figure 170)");
    test_rfc7520_jwe (&key, "rfc7520_figure171.jwe", "RFC 7520 5.9.  Compressed Content (figure 171)");
    test_rfc7520_jwe (&key, "rfc7520_figure172.jwe", "RFC 7520 5.9.  Compressed Content (figure 172)");

    // 5.10.  Including Additional Authenticated Data
    test_rfc7520_jwe (&key, "rfc7520_figure182.jwe", "RFC 7520 5.10.  Including Additional Authenticated Data (figure 182)");
    test_rfc7520_jwe (&key, "rfc7520_figure183.jwe", "RFC 7520 5.10.  Including Additional Authenticated Data (figure 183)");

    // 5.11.  Protecting Specific Header Fields
    test_rfc7520_jwe (&key, "rfc7520_figure192.jwe", "RFC 7520 5.11.  Protecting Specific Header Fields (figure 192)");
    test_rfc7520_jwe (&key, "rfc7520_figure193.jwe", "RFC 7520 5.11.  Protecting Specific Header Fields (figure 193)");

    // 5.12.  Protecting Content Only
    test_rfc7520_jwe (&key, "rfc7520_figure200.jwe", "RFC 7520 5.12.  Protecting Content Only (figure 200)");
    test_rfc7520_jwe (&key, "rfc7520_figure201.jwe", "RFC 7520 5.12.  Protecting Content Only (figure 201)");

    // 5.13.  Encrypting to Multiple Recipients
    test_rfc7520_jwe (&key, "rfc7520_figure221.jwe", "RFC 7520 5.13.  General JWE JSON Serialization (figure 221)");
}

void test_rfc7520_6_nesting_sig_and_enc ()
{
    print_text ("RFC 7520 6.  Nesting Signatures and Encryption");
    json_web_key jwk;
    crypto_key key;

    jwk.load_file (&key, "rfc7520_6.jwk");
    key.for_each (dump_crypto_key, nullptr);

    // 6.  Nesting Signatures and Encryption
    test_rfc7520_signature (&key, "rfc7520_figure228.jws", "RFC 7520 6.  Nesting Signatures and Encryption (figure 228)");
    test_rfc7520_jwe (&key, "rfc7520_figure236.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 236)");
    test_rfc7520_jwe (&key, "rfc7520_figure237.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 237)");
    test_rfc7520_jwe (&key, "rfc7520_figure238.jwe", "RFC 7520 6.  Nesting Signatures and Encryption (figure 238)");
}

void test_jwe_flattened ()
{
    print_text ("JWE");

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
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        jwk.load_file (&crypto_pubkey, "rfc7520_pub.jwk");
        jwk.load_file (&crypto_privkey, "rfc7520_priv.jwk");

        crypto_pubkey.for_each (dump_crypto_key, nullptr);
        crypto_privkey.for_each (dump_crypto_key, nullptr);

        jose.open (&handle_encrypt, &crypto_pubkey);
        jose.open (&handle_decrypt, &crypto_privkey);

        jwe_t encs [] = {
            jwe_t::jwe_a128cbc_hs256, jwe_t::jwe_a192cbc_hs384, jwe_t::jwe_a256cbc_hs512,
            jwe_t::jwe_a128gcm, jwe_t::jwe_a192gcm, jwe_t::jwe_a256gcm,
        };
        jwa_t algs [] = {
            jwa_t::jwa_rsa_1_5, jwa_t::jwa_rsa_oaep, jwa_t::jwa_rsa_oaep_256,
            jwa_t::jwa_a128kw, jwa_t::jwa_a192kw, jwa_t::jwa_a256kw,
            jwa_t::jwa_dir,
            jwa_t::jwa_ecdh_es,
            jwa_t::jwa_ecdh_es_a128kw, jwa_t::jwa_ecdh_es_a192kw, jwa_t::jwa_ecdh_es_a256kw,
            jwa_t::jwa_a128gcmkw, jwa_t::jwa_a192gcmkw, jwa_t::jwa_a256gcmkw,
            jwa_t::jwa_pbes2_hs256_a128kw, jwa_t::jwa_pbes2_hs384_a192kw, jwa_t::jwa_pbes2_hs512_a256kw,
        };

        for (size_t i = 0; i < RTL_NUMBER_OF (encs); i++) {
            jwe_t enc = encs [i];
            const char* nameof_enc = advisor->nameof_jose_encryption (encs [i]);

            for (size_t j = 0; j < RTL_NUMBER_OF (algs); j++) {
                jwa_t alg = algs [j];
                const char* nameof_alg = advisor->nameof_jose_algorithm (algs [j]);
                if (nameof_alg) {
                    print_text ("JWE enc %s alg %s", nameof_enc, nameof_alg);

                    ret = jose.encrypt (handle_encrypt, enc, alg, convert (input), encrypted, jose_serialization_t::jose_flatjson);
                    if (errorcode_t::success == ret) {
                        printf ("encrypted\n%s\n", encrypted.c_str ());

                        ret = jose.decrypt (handle_decrypt, encrypted, output, result);
                        dump_memory (&output [0], output.size (), &bs);
                        printf ("decrypted\n%s\n", bs.c_str ());
                    }
                    _test_case.test (ret, __FUNCTION__, "RFC 7520 JWE enc %s alg %s", nameof_enc, nameof_alg);
                }
            }
        }
    }
    __finally2
    {
        jose.close (handle_encrypt);
        jose.close (handle_decrypt);
    }
}

void test_jwe_json (jwe_t enc)
{
    print_text ("JWE");

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

    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const char* nameof_enc = advisor->nameof_jose_encryption (enc);

    __try2
    {
        jwk.load_file (&crypto_pubkey, "rfc7520_pub.jwk");
        jwk.load_file (&crypto_privkey, "rfc7520_priv.jwk");

        crypto_pubkey.for_each (dump_crypto_key, nullptr);
        crypto_privkey.for_each (dump_crypto_key, nullptr);

        jose.open (&handle_encrypt, &crypto_pubkey);
        jose.open (&handle_decrypt, &crypto_privkey);
        std::list<jwa_t> algs;

        algs.push_back (jwa_t::jwa_rsa_1_5);
        algs.push_back (jwa_t::jwa_rsa_oaep);
        algs.push_back (jwa_t::jwa_rsa_oaep_256);
        algs.push_back (jwa_t::jwa_a128kw);
        algs.push_back (jwa_t::jwa_a192kw);
        algs.push_back (jwa_t::jwa_a256kw);
        algs.push_back (jwa_t::jwa_dir);
        //algs.push_back (jwa_t::jwa_ecdh_es);
        algs.push_back (jwa_t::jwa_ecdh_es_a128kw);
        algs.push_back (jwa_t::jwa_ecdh_es_a192kw);
        algs.push_back (jwa_t::jwa_ecdh_es_a256kw);
        algs.push_back (jwa_t::jwa_a128gcmkw);
        algs.push_back (jwa_t::jwa_a192gcmkw);
        algs.push_back (jwa_t::jwa_a256gcmkw);
        algs.push_back (jwa_t::jwa_pbes2_hs256_a128kw);
        algs.push_back (jwa_t::jwa_pbes2_hs384_a192kw);
        algs.push_back (jwa_t::jwa_pbes2_hs512_a256kw);

        print_text ("JWE enc %s", nameof_enc);

        ret = jose.encrypt (handle_encrypt, enc, algs, convert (input), encrypted, jose_serialization_t::jose_json);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        printf ("encrypted\n%s\n", encrypted.c_str ());

        ret = jose.decrypt (handle_decrypt, encrypted, output, result);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2
    {
        jose.close (handle_encrypt);
        jose.close (handle_decrypt);
    }
    _test_case.test (ret, __FUNCTION__, "RFC 7520 JWE enc %s", nameof_enc);
}

return_t hash_stream (const char* algorithm, byte_t* stream, size_t size, binary_t& value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        value.clear ();

        if (nullptr == algorithm || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        hash_context_t* handle = nullptr;
        openssl_hash openssl;
        ret = openssl.open_byname (&handle, algorithm, nullptr, 0);
        if (errorcode_t::success == ret) {
            openssl.hash (handle, stream, size, value);
            openssl.close (handle);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

void test_jwk_thumbprint ()
{
    print_text ("JSON Web Key (JWK) Thumbprint");

    //return_t ret = errorcode_t::success;
    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    crypto_key key;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string buffer;
    std::string thumbprint;
    json_t* json_root = nullptr;
    binary_t hash_value;
    basic_stream bs;

    jwk.load_file (&key, "rfc7638_3.jwk");
    key.for_each (dump_crypto_key, nullptr);

    std::cout
        << "key item : "
        << key.size ()
        << std::endl;

    EVP_PKEY* pkey = key.any ();
    key.get_public_key (pkey, pub1, pub2);

    std::cout
        << "x : "
        << base16_encode (pub1).c_str ()
        << std::endl
        << "y : "
        << base16_encode (pub2).c_str ()
        << std::endl;

    json_root = json_object ();
    json_object_set_new (json_root, "e", json_string (base64_encode (pub2, base64_encoding_t::base64url_encoding).c_str ()));
    json_object_set_new (json_root, "kty", json_string ("RSA"));
    json_object_set_new (json_root, "n", json_string (base64_encode (pub1, base64_encoding_t::base64url_encoding).c_str ()));
    char* contents = json_dumps (json_root, JSON_COMPACT);
    if (contents) {
        buffer = contents;
        free (contents);
    }
    json_decref (json_root);

    //replace (buffer, " ", "");
    dump_memory ((byte_t*) buffer.c_str (), buffer.size (), &bs);
    std::cout
        << "dump"
        << std::endl
        << bs.c_str ()
        << std::endl;

    std::cout << "[";
#if __cplusplus >= 201103L    // c++11
    for_each (buffer.begin (), buffer.end (), [] (char c) {
        printf ("%i,", c);
    });
#else
    for (std::string::iterator iter = buffer.begin (); iter != buffer.end (); iter++) {
        byte_t c = *iter;
        printf ("%i,", c);
    }
#endif
    std::cout << "]" << std::endl;

    hash_stream ("sha256", (byte_t*) buffer.c_str (), buffer.size (), hash_value);
    thumbprint = base64_encode (hash_value, base64_encoding_t::base64url_encoding);

    std::cout
        << "in lexicographic order : "
        << std::endl
        << buffer.c_str ()
        << std::endl
        << "hash : "
        << std::endl
        << base16_encode (hash_value).c_str ()
        << std::endl
        << "thumbprint :"
        << std::endl
        << thumbprint.c_str ()
        << std::endl;

    // crv, kty, x, y
    // e, kty, n
    // k, kty

    sample = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    bool result = (thumbprint == sample);
    _test_case.test (result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                     "RFC 7638 3.1.  Example JWK Thumbprint Computation");
}

void test_rfc8037 ()
{
    print_text ("RFC 8037");
    return_t ret = errorcode_t::success;
    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    crypto_key key;

    jwk.load_file (&key, "rfc8037_A_ed25519.jwk");
    key.for_each (dump_crypto_key, nullptr);

    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    EVP_PKEY* pkey = key.any ();
    key.get_key (pkey, pub1, pub2, priv);

    std::cout
        << "x : "
        << base16_encode (pub1).c_str ()
        << std::endl
        << "d : "
        << base16_encode (priv).c_str ()
        << std::endl;

    // {"alg":"EdDSA"}
    std::string claim = "Example of Ed25519 signing";
    std::string signature;
    bool result = false;

    ret = jws.sign (&key, jws_t::jws_eddsa, claim, signature);
    printf ("%s\n", signature.c_str ());
    _test_case.test (ret, __FUNCTION__, "RFC 8037 A.4.  Ed25519 Signing");

    ret = jws.verify (&key, signature, result);
    _test_case.test (ret, __FUNCTION__, "RFC 8037 A.5.  Ed25519 Validation");

    std::string signature_rfc8037_a5 = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCj"
                                       "P0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_Mu"
                                       "M0KAg";
    ret = jws.verify (&key, signature_rfc8037_a5, result);
    printf ("%s\n", signature.c_str ());
    _test_case.test (ret, __FUNCTION__, "RFC 8037 A.5.  Ed25519 Validation");

    jose_context_t* handle = nullptr;
    std::string encrypted;
    binary_t source;
    json_object_signing_encryption jose;

    crypto_key jwk_x25519;
    jwk.load_file (&jwk_x25519, "rfc8037_A_X25519.jwk");
    jwk_x25519.for_each (dump_crypto_key, nullptr);
    jose.open (&handle, &jwk_x25519);
    ret = jose.encrypt (handle, jwe_t::jwe_a128gcm, jwa_t::jwa_ecdh_es_a128kw, convert (claim), encrypted, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        printf ("RFC 8037 A.6.  ECDH-ES with X25519\n%s\n", encrypted.c_str ());
    }
    jose.close (handle);
    _test_case.test (ret, __FUNCTION__, "RFC 8037 A.6.  ECDH-ES with X25519");

    crypto_key jwk_x448;
    jwk.load_file (&jwk_x448, "rfc8037_A_X448.jwk");
    jwk_x448.for_each (dump_crypto_key, nullptr);
    jose.open (&handle, &jwk_x448);
    ret = jose.encrypt (handle, jwe_t::jwe_a256gcm, jwa_t::jwa_ecdh_es_a256kw, convert (claim), encrypted, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        printf ("RFC 8037 A.7.  ECDH-ES with X448\n%s\n", encrypted.c_str ());
    }
    jose.close (handle);
    _test_case.test (ret, __FUNCTION__, "RFC 8037 A.7.  ECDH-ES with X448");
}

void test_okp ()
{
    print_text ("JWE with OKP");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    crypto_key key;
    bool result = true;
    jose_context_t* handle = nullptr;

    basic_stream bs;
    std::string claim;
    std::string encrypted;
    binary_t source;
    std::string signature;

    key.generate (crypto_key_t::kty_okp, 25519, "test1", crypto_use_t::use_enc);
    key.generate (crypto_key_t::kty_okp, 25519, "test2", crypto_use_t::use_sig);
    key.generate (crypto_key_t::kty_okp, 448, "test3", crypto_use_t::use_enc);
    key.generate (crypto_key_t::kty_okp, 448, "test4", crypto_use_t::use_sig);
    key.for_each (dump_crypto_key, nullptr);

    jose.open (&handle, &key);

    jwe_t encs [] = {
        jwe_t::jwe_a128cbc_hs256,
        jwe_t::jwe_a192cbc_hs384,
        jwe_t::jwe_a256cbc_hs512,
        jwe_t::jwe_a128gcm,
        jwe_t::jwe_a192gcm,
        jwe_t::jwe_a256gcm,
    };
    jwa_t algs [] = {
        jwa_t::jwa_ecdh_es,
        jwa_t::jwa_ecdh_es_a128kw,
        jwa_t::jwa_ecdh_es_a192kw,
        jwa_t::jwa_ecdh_es_a256kw,
    };

    crypto_advisor* advisor = crypto_advisor::get_instance ();

    for (size_t i = 0; i < RTL_NUMBER_OF (encs); i++) {
        const char* nameof_enc = advisor->nameof_jose_encryption (encs [i]);
        for (size_t j = 0; j < RTL_NUMBER_OF (algs); j++) {
            ret = errorcode_t::success;
            const char* nameof_alg = advisor->nameof_jose_algorithm (algs [j]);
            claim = format ("JWE with OKP enc %s alg %s", nameof_enc, nameof_alg);

            ret = jose.encrypt (handle, encs [i], algs [j], convert (claim), encrypted, jose_serialization_t::jose_flatjson);
            if (errorcode_t::success == ret) {
                printf ("%s\n", encrypted.c_str ());
                ret = jose.decrypt (handle, encrypted, source, result);
                if (errorcode_t::success == ret) {
                    dump_memory (&source [0], source.size (), &bs, 32);
                    printf ("%s\n", bs.c_str ());
                }
            }
            _test_case.test (ret, __FUNCTION__, "RFC 8037 JWE with OKP enc %s alg %s", nameof_enc, nameof_alg);
        }
    }

    ret = jose.sign (handle, jws_t::jws_eddsa, claim, signature, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        printf ("%s\n", signature.c_str ());
        ret = jose.verify (handle, signature, result);
        _test_case.test (ret, __FUNCTION__, "RFC 8037 JWS with OKP");
    }
    jose.close (handle);
}

void key_dump (crypto_key* key, jwa_t alg, crypto_use_t use)
{
    EVP_PKEY* pkey = nullptr;
    //size_t key_length = 0;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string kid;
    std::string hex;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);

    print_text ("try kt %d alg %s", alg_info->kty, alg_info->alg_name);
    pkey = key->select (kid, alg, use);
    if (pkey) {
        printf ("> kid %s\n", kid.c_str ());
        key->get_key (pkey, pub1, pub2, priv);

        basic_stream bs;
        dump_key (pkey, &bs);
        printf ("%s\n", bs.c_str ());
    }
}

void key_dump (crypto_key* key, jws_t sig, crypto_use_t use)
{
    EVP_PKEY* pkey = nullptr;
    //size_t key_length = 0;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string kid;
    std::string hex;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_signature_t* alg_info = advisor->hintof_jose_signature (sig);

    print_text ("try kt %d alg %s", alg_info->kty, alg_info->jws_name);
    pkey = key->select (kid, sig, use);
    if (pkey) {
        printf ("> kid %s\n", kid.c_str ());
        key->get_key (pkey, pub1, pub2, priv);

        basic_stream bs;
        dump_key (pkey, &bs);
        printf ("%s\n", bs.c_str ());
    }
}

void key_match_test ()
{
    json_web_key jwk;

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        crypto_key key;
        jwk.load_file (&key, "keys.jwk");
        key.for_each (dump_crypto_key, nullptr);

        jwa_t algs [] = {
            jwa_t::jwa_rsa_1_5, jwa_t::jwa_rsa_oaep, jwa_t::jwa_rsa_oaep_256,
            jwa_t::jwa_a128kw, jwa_t::jwa_a192kw, jwa_t::jwa_a256kw,
            jwa_t::jwa_ecdh_es,
            jwa_t::jwa_ecdh_es_a128kw, jwa_t::jwa_ecdh_es_a192kw, jwa_t::jwa_ecdh_es_a256kw,
            jwa_t::jwa_a128gcmkw, jwa_t::jwa_a192gcmkw, jwa_t::jwa_a256gcmkw,
            jwa_t::jwa_pbes2_hs256_a128kw, jwa_t::jwa_pbes2_hs384_a192kw, jwa_t::jwa_pbes2_hs512_a256kw
        };
        for (unsigned int i = 0; i < RTL_NUMBER_OF (algs); i++) {
            key_dump (&key, algs[i], crypto_use_t::use_enc);
        }
    }
    __finally2
    {
    }

    __try2
    {
        crypto_key key;
        jwk.load_file (&key, "rfc7515.jwk");
        key.for_each (dump_crypto_key, nullptr);

        jws_t algs [] = {
            jws_t::jws_hs256, jws_t::jws_hs384, jws_t::jws_hs512,
            jws_t::jws_rs256, jws_t::jws_rs384, jws_t::jws_rs512,
            jws_t::jws_es256, jws_t::jws_es384, jws_t::jws_es512,
            jws_t::jws_ps256, jws_t::jws_ps384, jws_t::jws_ps512,
        };
        for (unsigned int i = 0; i < RTL_NUMBER_OF (algs); i++) {
            key_dump (&key, algs[i], crypto_use_t::use_sig);
        }
    }
    __finally2
    {
    }
}

int main (int argc, char** argv)
{
    set_trace_option (trace_option_t::trace_bt);

    _cmdline.make_share (new cmdline_t <OPTION>);
    *_cmdline << cmdarg_t<OPTION> ("-dump", "dump keys", [&](OPTION& o, char* param) -> void {
        o.dump_keys = true;
    }).optional ();
    (*_cmdline).parse (argc, argv);

    OPTION& option = _cmdline->value ();
    std::cout << "option.dump_keys " << (option.dump_keys ? 1 : 0) << std::endl;

    openssl_startup ();
    openssl_thread_setup ();

    test0 ();

    _test_case.begin ("RFC 7515");

    test_rfc7515_A1 ();
    test_rfc7515_HS ();
    test_rfc7515_A2 ();
    test_rfc7515_A3 ();
    test_rfc7515_A4 ();
    test_rfc7515_A5 ();
    test_rfc7515_A6 ();
    test_rfc7515_A7 ();

    _test_case.begin ("RFC 7515 PEM");
    test_rfc7515_bypem ();
    _test_case.begin ("RFC 7515 key generation");
    test_rfc7515_bykeygen ();

    _test_case.begin ("key matching");
    key_match_test ();

    _test_case.begin ("RFC 7516");

    test_rfc7516_A1_test ();
    test_rfc7516_A1 ();     // RSAES-OAEP and AES GCM

    test_rsa_oaep_256 ();
    test_rsa_oaep ();

    test_rfc7516_A2 ();     // RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
    test_rfc7516_A3 ();     // AES Key Wrap and AES_128_CBC_HMAC_SHA_256
    test_rfc7516_A4 ();     // Example JWE Using General JWE JSON Serialization

    test_rfc7516_B ();

    _test_case.begin ("RFC 7517");
    test_jwk ();
    test_rfc7517_C (); // RFC 7517 Appendix C.

    _test_case.begin ("RFC 7518");
    test_rfc7518_RSASSA_PSS (); // test
    test_ecdh ();
    test_rfc7518_C ();

    _test_case.begin ("RFC 7520");
    test_rfc7520 ();
    test_rfc7520_6_nesting_sig_and_enc ();

    test_jwe_flattened ();
    test_jwe_json (jwe_t::jwe_a128cbc_hs256);
    test_jwe_json (jwe_t::jwe_a192cbc_hs384);
    test_jwe_json (jwe_t::jwe_a256cbc_hs512);
    test_jwe_json (jwe_t::jwe_a128gcm);
    test_jwe_json (jwe_t::jwe_a192gcm);
    test_jwe_json (jwe_t::jwe_a256gcm);

    _test_case.begin ("RFC 7638");
    test_jwk_thumbprint ();

    _test_case.begin ("RFC 8037");
    test_rfc8037 ();
    test_okp ();

    openssl_thread_cleanup ();
    openssl_cleanup ();

    _test_case.report (20);
    return _test_case.result ();
}

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

void test_x509_sign() {
    _test_case.begin("RSA sign/verify");

    // generated self-signed certificate
    const char* pem =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEArZopZ1/zpHm0xuYyc9jX7YiUFYPkMQAEbLWMrIerdEQTdsoL\n"
        "dClAnpcqAdeLRiZuGTVNwNO16g6TOgbo5YW1JwVj2yi4ktpaFDkP2mhtbwr7UtwI\n"
        "D1TT5KIonaBxUILg28rRlN1CmDoJM6jZ7/vSNUOxIqK+QW26kdwLMU6I+U2cYS3s\n"
        "shMKwpGOotbpQLkyuYCPsxijMxMj1dB+2dB/k+AtTZDFWCRW1ckQE0qymSN9NLmO\n"
        "lxlpb87GP9YXp9JD4DbLUXsvGIvCM/hXz9FhC3ztNzXjE3okLncIwuPZ5hfTpcY0\n"
        "WtqGp/gCNh1mY8/pwD2C+zmijZIBSoPP4nY9hwIDAQABAoIBAH4rr/HY08vzRIbW\n"
        "YU6/B9g0TmQAsoVGXPDhVfdCt0LOA1NvbrmjDbr1ZGtoS2nVnmkly3fcprcQlsIy\n"
        "qWu/LLTKfxOWWecpWRSfkD0NbpOo6JYFIrp5zXK6xEgjhpecN26mzoGh+beHXo60\n"
        "Joj7fYCGzSO+IgaNiG5f/aZ9TKHbKorj/Cg9iKb4HjnDW0xcT44xTXbwlWalePfI\n"
        "JyovjP5iOfwQOY4VP34+wbdaejh6yKn5u+Vt154cYv/mk0E63HnnHuVJYRYdpoNa\n"
        "tTJ7tzJG7G3iA0vT9O2NOL7Xz8HF8jQ2R/duWAaoSmp3V5Z57Kz9sIwCjy2EKNnk\n"
        "cTPf6qkCgYEA3OPpAE8fGJHkBvTDKWeR9BDtuRAhVBDeV65rawoFYkE9gJJUW45g\n"
        "1aOKsXuTim3SW9M1ozHhcX76aDXzO44GUB4OWTZU0rXn1pF4ketWVaaeOtK08z+Z\n"
        "PhmHeWu66ntOyxXJcNMeBDrhTFWyBW67GvXresziiZ4zmoe6L1VZO8MCgYEAyTIV\n"
        "9Z0U2El46/+c43/1K2oe87kPnIhhCG3h+qwxeUtPAWxv5ilJ1eoLawNLHjMPz73D\n"
        "gJhGGoWAzTpUhwVmNiycSWKwurEQMd2EWAiaqPDy5BfQ1d5y94qR6RCF83orTF5C\n"
        "K8tsTRUsgRfvfiSGpF5fvWOUuN486PTGkYcBzu0CgYAGsLyA7uSROPIAJ++1VFa+\n"
        "XrjkjxGDW1Nwsm68ejw5gqJbP5Nghop2ThLIV2bbnYHumBIa1ErwxhjNiTzJw/56\n"
        "9L4Yg6XEEBBqllNhkBA4XeiS/YjPiVCZ6eoJinLJ4Vw8mHdWfH5/QE1Mo5fVxEnU\n"
        "gjhUqtn9sxX7CztfbaVbQwKBgDh77jxRSEvcfK1Myt/3yX3RwjTMbLyWcR9rsfit\n"
        "JQqXgOu2ZMfqKYd7uI7nksw8q6C39s4AchX6CwoS6S4q7uIgrhPQOCuBkDlfpksM\n"
        "x1bMpnQw13ljhUVHyuTytZiAYO2EvPEMoDAX1LG9ZYg1evNkZ16FOXiZM+J27dRn\n"
        "YbOVAoGBAMLfSTx7DU5OnntkvZSHypq8Qnc5A4yyA6tqqCWhUrgUs4sXPIOZcCGP\n"
        "P5t54dqVCzslaYzSSO3dZ6H9DODFE1RPf7EH5a3ysMnwrgpsK1lbEK9D1TjNEnYy\n"
        "Eeef6g+xbyHS2w7OL1so7ubkTcGeARVfNYj8fUQm2wwsfVOfk13r\n"
        "-----END RSA PRIVATE KEY-----\n";
    const char* crt =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDXDCCAkSgAwIBAgIUY6ZxEHnWpkhZ2mepBOjjX+IDoyYwDQYJKoZIhvcNAQEL\n"
        "BQAwWTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsG\n"
        "A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4X\n"
        "DTI0MDgyOTA2MjcxN1oXDTI1MDgyOTA2MjcxN1owVDELMAkGA1UEBhMCS1IxCzAJ\n"
        "BgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwE\n"
        "VGVzdDENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
        "ggEBAK2aKWdf86R5tMbmMnPY1+2IlBWD5DEABGy1jKyHq3REE3bKC3QpQJ6XKgHX\n"
        "i0Ymbhk1TcDTteoOkzoG6OWFtScFY9souJLaWhQ5D9pobW8K+1LcCA9U0+SiKJ2g\n"
        "cVCC4NvK0ZTdQpg6CTOo2e/70jVDsSKivkFtupHcCzFOiPlNnGEt7LITCsKRjqLW\n"
        "6UC5MrmAj7MYozMTI9XQftnQf5PgLU2QxVgkVtXJEBNKspkjfTS5jpcZaW/Oxj/W\n"
        "F6fSQ+A2y1F7LxiLwjP4V8/RYQt87Tc14xN6JC53CMLj2eYX06XGNFrahqf4AjYd\n"
        "ZmPP6cA9gvs5oo2SAUqDz+J2PYcCAwEAAaMhMB8wHQYDVR0RBBYwFIISdGVzdC5w\n"
        "cmluY2ViNjEyLnBlMA0GCSqGSIb3DQEBCwUAA4IBAQAApfVUGKutNjjI/AtmYN2f\n"
        "dZ2GW3kv7lfxeRwVoTQj0BypWFGk0Aj12PdJ6cW1ZZFRLW3kOw53Ah9FjjTlu+v2\n"
        "nd9KQGAhs44WMz/0tpDTPDTO5tlHB6dXFAz5eAs2cqmIBweTtNf+KV7oQTcgpQPH\n"
        "l8uCytsU5YuWH6npID1rJa70iUxgjekUM0dLiFSiRxmByHsOMlIrkYitD21zMIwA\n"
        "r9X8RkavOsIXiezIg67a5mlj4JyEIsV63ugja1Odb5TSf1y+HQzeDgcNUqVDjOgF\n"
        "78D/8HP63FpRTCQJZUV9q1KLfl3w+96nPUPFr3bjbvmh3HiivVRBBJnlVjK6Av1y\n"
        "-----END CERTIFICATE-----\n";

    return_t ret = errorcode_t::success;
    const char* source = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(source);
    crypto_key key;
    crypto_keychain keychain;
    keychain.load_pem(&key, pem, strlen(pem), keydesc("priv"));
    keychain.load_cert(&key, crt, strlen(crt), keydesc("pub"));

    auto pkey_priv = key.find("priv");
    auto pkey_pub = key.find("pub");

    _logger->write([&](basic_stream& bs) -> void { dump_key(pkey_priv, &bs); });
    _test_case.assert(pkey_priv, __FUNCTION__, "load RSA private key");

    _logger->write([&](basic_stream& bs) -> void { dump_key(pkey_pub, &bs); });
    _test_case.assert(pkey_pub, __FUNCTION__, "load RSA certificate");

    crypto_sign_builder builder;
    {
        auto s = builder.set_scheme(crypt_sig_rsassa_pkcs15).set_digest(sha2_256).build();
        if (s) {
            binary_t signature;

            ret = s->sign(pkey_priv, (const byte_t*)source, len, signature);
            _test_case.test(ret, __FUNCTION__, "PKCS#1 Ver1.5 sign");

            _logger->hdump("> signature", signature);

            ret = s->verify(pkey_pub, (const byte_t*)source, len, signature);
            _test_case.test(ret, __FUNCTION__, "PKCS#1 Ver1.5 verify");

            s->release();
        }
    }
    {
        auto s = builder.set_scheme(crypt_sig_rsassa_pss).set_digest(sha2_256).build();
        if (s) {
            binary_t signature;

            ret = s->sign(pkey_priv, (const byte_t*)source, len, signature);
            _test_case.test(ret, __FUNCTION__, "PKCS#1 RSASSA-PSS sign");

            _logger->hdump("> signature", signature);

            ret = s->verify(pkey_pub, (const byte_t*)source, len, signature);
            _test_case.test(ret, __FUNCTION__, "PKCS#1 RSASSA-PSS verify");

            s->release();
        }
    }
}

/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tlsspec.hpp>

namespace hotplace {
namespace net {

tls_resource tls_resource::_instance;

tls_resource* tls_resource::get_instance() {
    if (false == _instance._load) {
        critical_section_guard guard(_instance._lock);
        if (false == _instance._load) {
            _instance.load_resource();
            _instance._load = true;
        }
    }
    return &_instance;
}

tls_resource::tls_resource() : _load(false) {}

tls_resource::~tls_resource() {}

void tls_resource::load_resource() {
    load_tls_version();
    load_cipher_suites();
    load_named_curves();
    load_signature_schemes();
}

void tls_resource::load_tls_version() {
    // 0x0304
    //  RFC 8446
    //   4.1.2.  Client Hello - see legacy_version
    //   4.2.1.  Supported Versions
    //   5.1.  Record Layer
    //   9.2.  Mandatory-to-Implement Extensions

    _tls_version.insert({0x0303, "TLS v1.2"});  // RFC 5246 A.1.  Record Layer
    // deprecated
    _tls_version.insert({0x0302, "TLS v1.1"});  // RFC 4346 A.1. Record Layer
    _tls_version.insert({0x0301, "TLS v1.0"});  // RFC 2246 A.1. Record layer
}

void tls_resource::load_cipher_suites() {
    // TLS_{Key Exchange}_{Cipher}_{Mac}

    // RFC 8446 B.4.  Cipher Suites
    _cipher_suites.insert({0x1301, "TLS_AES_128_GCM_SHA256"});        // madatory, MUST
    _cipher_suites.insert({0x1302, "TLS_AES_256_GCM_SHA384"});        // madatory, SHOULD
    _cipher_suites.insert({0x1303, "TLS_CHACHA20_POLY1305_SHA256"});  // madatory, SHOULD
    _cipher_suites.insert({0x1304, "TLS_AES_128_CCM_SHA256"});
    _cipher_suites.insert({0x1305, "TLS_AES_128_CCM_8_SHA256"});
    // RFC 5246 A.5.  The Cipher Suite
    _cipher_suites.insert({0x0000, "TLS_NULL_WITH_NULL_NULL"});  // MUST NOT be negotiated
    _cipher_suites.insert({0x0001, "TLS_RSA_WITH_NULL_MD5"});
    _cipher_suites.insert({0x0001, "TLS_RSA_WITH_NULL_MD5"});
    _cipher_suites.insert({0x0002, "TLS_RSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0x003b, "TLS_RSA_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x0004, "TLS_RSA_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x0005, "TLS_RSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"});

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
}

void tls_resource::load_named_curves() {
    _named_curves.insert({0x0017, "secp256r1"});
    _named_curves.insert({0x0018, "secp384r1"});
    _named_curves.insert({0x0019, "secp521r1"});
    _named_curves.insert({0x001d, "x25519"});
    _named_curves.insert({0x001e, "x448"});
    _named_curves.insert({0x0100, "ffdhe2048"});
    _named_curves.insert({0x0101, "ffdhe3072"});
    _named_curves.insert({0x0102, "ffdhe4096"});
    _named_curves.insert({0x0103, "ffdhe6144"});
    _named_curves.insert({0x0104, "ffdhe8192"});
}

void tls_resource::load_signature_schemes() {
    _signature_schemes.insert({0x0401, "rsa_pkcs1_sha256"});
    _signature_schemes.insert({0x0501, "rsa_pkcs1_sha384"});
    _signature_schemes.insert({0x0601, "rsa_pkcs1_sha512"});
    _signature_schemes.insert({0x0403, "ecdsa_secp256r1_sha256"});
    _signature_schemes.insert({0x0503, "ecdsa_secp384r1_sha384"});
    _signature_schemes.insert({0x0603, "ecdsa_secp521r1_sha512"});
    _signature_schemes.insert({0x0804, "rsa_pss_rsae_sha256"});
    _signature_schemes.insert({0x0805, "rsa_pss_rsae_sha384"});
    _signature_schemes.insert({0x0806, "rsa_pss_rsae_sha512"});
    _signature_schemes.insert({0x0807, "ed25519"});
    _signature_schemes.insert({0x0808, "ed448"});
    _signature_schemes.insert({0x0809, "rsa_pss_pss_sha256"});
    _signature_schemes.insert({0x080a, "rsa_pss_pss_sha384"});
    _signature_schemes.insert({0x080b, "rsa_pss_pss_sha512"});
    _signature_schemes.insert({0x0201, "rsa_pkcs1_sha1"});
    _signature_schemes.insert({0x0203, "ecdsa_sha1"});
}

std::string tls_resource::tls_version_string(uint16 code) {
    std::string value;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_resource::cipher_suite_string(uint16 code) {
    std::string value;
    auto iter = _cipher_suites.find(code);
    if (_cipher_suites.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_resource::compression_method_string(uint8 code) {
    std::string value;
    if (0 == code) {
        value = "null";
    }
    return value;
}

std::string tls_resource::sni_nametype_string(uint16 code) {
    std::string value;
    if (0 == code) {
        value = "hostname";
    }
    return value;
}

std::string tls_resource::named_curve_string(uint16 code) {
    std::string value;
    auto iter = _named_curves.find(code);
    if (_named_curves.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_resource::signature_scheme_string(uint16 code) {
    std::string value;
    auto iter = _signature_schemes.find(code);
    if (_signature_schemes.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace net
}  // namespace hotplace

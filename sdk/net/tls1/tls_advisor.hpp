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

#ifndef __HOTPLACE_SDK_NET_TLS1X_TLSADVISOR__
#define __HOTPLACE_SDK_NET_TLS1X_TLSADVISOR__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

/**
 * declare_tls_resource(cipher_suite_code, uint16);
 * define_tls_variable(cipher_suite_code) = {
 *   // ...
 * };
 *
 *
 * struct tls_cipher_suite_code_t {
 *     uint16 code;
 *     const char* desc;
 * };
 * extern const tls_cipher_suite_code_t tls_cipher_suite_codes[];
 * extern const size_t sizeof_tls_cipher_suite_codes;
 *
 * const tls_cipher_suite_code_t tls_cipher_suite_codes[] = {
 *     // ...
 * };
 * const size_t sizeof_tls_cipher_suite_codes = RTL_NUMBER_OF(tls_cipher_suite_codes);
 */
#define declare_tls_resource(name, code_type)    \
    struct tls_##name##_t {                      \
        code_type code;                          \
        const char* desc;                        \
    };                                           \
    extern const tls_##name##_t tls_##name##s[]; \
    extern const size_t sizeof_tls_##name##s;
#define define_tls_variable(name) const tls_##name##_t tls_##name##s[]
#define define_tls_sizeof_variable(name) const size_t sizeof_tls_##name##s = RTL_NUMBER_OF(tls_##name##s)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
declare_tls_resource(alert_code, uint8);
declare_tls_resource(alert_level_code, uint8);
declare_tls_resource(client_cert_type_code, uint8);
declare_tls_resource(content_type_code, uint8);
declare_tls_resource(ec_curve_type_code, uint8);
declare_tls_resource(ec_point_format_code, uint8);
declare_tls_resource(handshake_type_code, uint8);
declare_tls_resource(hash_alg_code, uint8);
declare_tls_resource(kdf_id_code, uint16);
declare_tls_resource(psk_keyexchange_code, uint8);
declare_tls_resource(sig_alg_code, uint8);
declare_tls_resource(supported_group_code, uint16);

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
declare_tls_resource(compression_alg_code, uint16);
declare_tls_resource(cert_status_type_code, uint8);
declare_tls_resource(cert_type_code, uint8);
declare_tls_resource(extension_type_code, uint16);

// https://www.iana.org/assignments/quic/quic.xhtml
declare_tls_resource(quic_trans_param_code, uint64);

// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
declare_tls_resource(aead_alg_code, uint16);

/**
 * @brief   cipher suites
 * @remarks
 *          cs_std, cs_ossl https://docs.openssl.org/1.1.1/man1/ciphers/
 */
struct tls_cipher_suite_t {
    uint16 code;                // 0xc023
    tls_version_t version;      // tls_12
    uint8 secure;               // 0 : insecure or weak
    uint8 support;              //
    const char* name_iana;      // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    const char* name_ossl;      // ECDHE-ECDSA-AES128-SHA256
    keyexchange_t keyexchange;  // keyexchange_ecdhe
    auth_t auth;                // auth_ecdsa
    crypt_algorithm_t cipher;   // aes128
    crypt_mode_t mode;          // cbc
    hash_algorithm_t mac;       // sha2_256
};
extern const tls_cipher_suite_t tls_cipher_suites[];
extern const size_t sizeof_tls_cipher_suites;
hash_algorithm_t algof_mac(const tls_cipher_suite_t* info);

struct tls_sig_scheme_t {
    uint16 code;
    uint8 pri;
    crypto_kty_t kty;
    crypt_sig_type_t sigtype;  // crypt_sig_rsassa_pkcs15, crypt_sig_ecdsa, crypt_sig_rsassa_pss, crypt_sig_eddsa
    uint32 nid;
    crypt_sig_t sig;  // sig_rs256, ..., sig_es256, ..., sig_ps256, ..., sig_eddsa, sig_sha1, sig_sha256, ...
    const char* name;
};
extern const tls_sig_scheme_t tls_sig_schemes[];
extern const size_t sizeof_tls_sig_schemes;

class tls_advisor {
   public:
    static tls_advisor* get_instance();
    ~tls_advisor();

    const tls_cipher_suite_t* hintof_cipher_suite(uint16 code);
    const tls_cipher_suite_t* hintof_cipher_suite(const std::string& name);
    const hint_blockcipher_t* hintof_blockcipher(uint16 code);
    const hint_digest_t* hintof_digest(uint16 code);
    const tls_sig_scheme_t* hintof_signature_scheme(uint16 code);
    const tls_sig_scheme_t* hintof_signature_scheme(const std::string& name);
    hash_algorithm_t hash_alg_of(uint16 code);

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    std::string alert_level_string(uint8 code);
    std::string alert_desc_string(uint8 code);
    std::string cipher_suite_string(uint16 code);
    uint16 cipher_suite_code(const std::string& ciphersuite);
    std::string content_type_string(uint8 type);
    std::string ec_curve_type_string(uint8 code);
    std::string ec_point_format_name(uint8 code);
    uint16 ec_point_format_code(const std::string& name);
    std::string handshake_type_string(uint8 type);
    std::string kdf_id_string(uint16 type);
    std::string psk_key_exchange_mode_name(uint8 code);
    uint8 psk_key_exchange_mode_code(const std::string& name);
    std::string signature_scheme_name(uint16 code);
    uint16 signature_scheme_code(const std::string& name);
    std::string supported_group_name(uint16 code);
    uint16 supported_group_code(const std::string& name);

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    std::string compression_alg_name(uint16 code);
    uint16 compression_alg_code(const std::string& name);
    std::string tls_extension_string(uint16 code);
    std::string cert_status_type_string(uint8 code);

    // https://www.iana.org/assignments/quic/quic.xhtml
    std::string quic_param_string(uint64 code);

    // https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
    std::string aead_alg_string(uint16 code);

    // etc

    std::string tls_version_string(uint16 code);
    std::string compression_method_string(uint8 code);
    std::string sni_nametype_string(uint16 code);

    bool is_kindof_tls13(uint16 ver);
    bool is_kindof_tls(uint16 ver);
    bool is_kindof_dtls(uint16 ver);
    /**
     * tlsadvisor->is_kindof(tls_12, dtls_12);
     * tlsadvisor->is_kindof(tls_13, dtls_13);
     */
    bool is_kindof(uint16 lhs, uint16 rhs);

   protected:
    tls_advisor();
    void load_resource();
    void load_tls_parameters();
    void load_tls_extensiontype_values();
    void load_tls_quic();
    void load_tls_aead_parameters();

    void load_tls_version();

    static tls_advisor _instance;
    critical_section _lock;

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    std::map<uint8, const tls_alert_level_code_t*> _alert_level_codes;
    std::map<uint8, const tls_alert_code_t*> _alert_codes;
    std::map<uint16, const tls_cipher_suite_t*> _cipher_suite_codes;
    std::map<std::string, const tls_cipher_suite_t*> _cipher_suite_names;
    std::map<uint8, const tls_client_cert_type_code_t*> _client_cert_type_codes;
    std::map<uint8, const tls_content_type_code_t*> _content_type_codes;
    std::map<uint8, const tls_ec_curve_type_code_t*> _ec_curve_type_codes;
    std::map<uint8, const tls_ec_point_format_code_t*> _ec_point_format_codes;
    std::map<std::string, const tls_ec_point_format_code_t*> _ec_point_format_names;
    std::map<uint8, const tls_handshake_type_code_t*> _handshake_type_codes;
    std::map<uint8, const tls_kdf_id_code_t*> _kdf_id_codes;
    std::map<uint8, const tls_psk_keyexchange_code_t*> _psk_keyexchange_codes;
    std::map<std::string, const tls_psk_keyexchange_code_t*> _psk_keyexchange_names;
    std::map<uint16, const tls_sig_scheme_t*> _sig_scheme_codes;
    std::map<std::string, const tls_sig_scheme_t*> _sig_scheme_names;
    std::map<uint16, const tls_supported_group_code_t*> _supported_group_codes;
    std::map<std::string, const tls_supported_group_code_t*> _supported_group_names;

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    std::map<uint16, const tls_compression_alg_code_t*> _compression_alg_codes;
    std::map<std::string, const tls_compression_alg_code_t*> _compression_alg_names;
    std::map<uint16, const tls_extension_type_code_t*> _extension_type_codes;
    std::map<uint8, const tls_cert_status_type_code_t*> _cert_status_type_codes;

    // https://www.iana.org/assignments/quic/quic.xhtml
    std::map<uint64, const tls_quic_trans_param_code_t*> _quic_trans_param_codes;

    // https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
    std::map<uint16, const tls_aead_alg_code_t*> _aead_alg_codes;

    std::map<uint16, std::string> _tls_version;
    std::map<uint8, std::string> _cert_status_types;

    bool _load;
};

}  // namespace net
}  // namespace hotplace

#endif

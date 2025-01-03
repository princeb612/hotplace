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
 * declare_tls_resource(cipher_suite_desc, uint16);
 * define_tls_variable(cipher_suite_desc) = {
 *   // ...
 * };
 *
 *
 * struct tls_cipher_suite_desc_t {
 *     uint16 code;
 *     const char* desc;
 * };
 * extern const tls_cipher_suite_desc_t tls_cipher_suite_descs[];
 * extern const size_t sizeof_tls_cipher_suite_descs;
 *
 * const tls_cipher_suite_desc_t tls_cipher_suite_descs[] = {
 *     // ...
 * };
 * const size_t sizeof_tls_cipher_suite_descs = RTL_NUMBER_OF(tls_cipher_suite_descs);
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
declare_tls_resource(alert_desc, uint8);
declare_tls_resource(alert_level_desc, uint8);
declare_tls_resource(cipher_suite_desc, uint16);
declare_tls_resource(client_cert_type_desc, uint8);
declare_tls_resource(content_type_desc, uint8);
declare_tls_resource(ec_curve_type_desc, uint8);
declare_tls_resource(ec_point_format_desc, uint8);
declare_tls_resource(handshake_type_desc, uint8);
declare_tls_resource(hash_alg_desc, uint8);
declare_tls_resource(kdf_id_desc, uint16);
declare_tls_resource(psk_keyexchange_desc, uint8);
declare_tls_resource(sig_alg_desc, uint8);
declare_tls_resource(supported_group_desc, uint16);

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
declare_tls_resource(cert_compression_algid_desc, uint16);
declare_tls_resource(cert_status_type_desc, uint8);
declare_tls_resource(cert_type_desc, uint8);
declare_tls_resource(extension_type_desc, uint16);

// https://www.iana.org/assignments/quic/quic.xhtml
declare_tls_resource(quic_trans_param_desc, uint64);

// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
declare_tls_resource(aead_alg_desc, uint16);

struct tls_cipher_suite_t {
    uint16 alg;
    crypt_algorithm_t cipher;
    crypt_mode_t mode;
    uint8 tagsize;
    hash_algorithm_t mac;
    hash_algorithm_t mac_tls1;
};
extern const tls_cipher_suite_t tls_cipher_suites[];
extern const size_t sizeof_tls_cipher_suites;
hash_algorithm_t algof_mac(const tls_cipher_suite_t* info);
hash_algorithm_t algof_mac1(const tls_cipher_suite_t* info);

struct tls_sig_scheme_t {
    uint16 code;
    crypt_sig_type_t sigtype;  // crypt_sig_rsassa_pkcs15, crypt_sig_ecdsa, crypt_sig_rsassa_pss, crypt_sig_eddsa
    uint32 nid;
    crypt_sig_t sig;  // sig_rs256, ..., sig_es256, ..., sig_ps256, ..., sig_eddsa, sig_sha1, sig_sha256, ...
    const char* desc;
};
extern const tls_sig_scheme_t tls_sig_schemes[];
extern const size_t sizeof_tls_sig_schemes;

class tls_advisor {
   public:
    static tls_advisor* get_instance();
    ~tls_advisor();

    const tls_cipher_suite_t* hintof_cipher_suite(uint16 code);
    const hint_blockcipher_t* hintof_blockcipher(uint16 code);
    const hint_digest_t* hintof_digest(uint16 code);
    const tls_sig_scheme_t* hintof_signature_scheme(uint16 code);
    hash_algorithm_t hash_alg_of(uint16 code);

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    std::string alert_level_string(uint8 code);
    std::string alert_desc_string(uint8 code);
    std::string cipher_suite_string(uint16 code);
    std::string content_type_string(uint8 type);
    std::string ec_curve_type_string(uint8 code);
    std::string ec_point_format_string(uint8 code);
    std::string handshake_type_string(uint8 type);
    std::string kdf_id_string(uint16 type);
    std::string psk_key_exchange_mode_string(uint8 mode);
    std::string signature_scheme_string(uint16 code);
    std::string supported_group_string(uint16 code);

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    std::string cert_compression_algid_string(uint16 code);
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

    bool is_basedon_tls13(uint16 ver);
    bool is_kindof_tls(uint16 ver);
    bool is_kindof_dtls(uint16 ver);

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
    std::map<uint8, const tls_alert_level_desc_t*> _alert_level_descs;
    std::map<uint8, const tls_alert_desc_t*> _alert_descs;
    std::map<uint16, const tls_cipher_suite_desc_t*> _cipher_suite_descs;
    std::map<uint8, const tls_client_cert_type_desc_t*> _client_cert_type_descs;
    std::map<uint8, const tls_content_type_desc_t*> _content_type_descs;
    std::map<uint8, const tls_ec_curve_type_desc_t*> _ec_curve_type_descs;
    std::map<uint8, const tls_ec_point_format_desc_t*> _ec_point_format_descs;
    std::map<uint8, const tls_handshake_type_desc_t*> _handshake_type_descs;
    std::map<uint8, const tls_kdf_id_desc_t*> _kdf_id_descs;
    std::map<uint8, const tls_psk_keyexchange_desc_t*> _psk_keyexchange_descs;
    std::map<uint16, const tls_sig_scheme_t*> _sig_schemes;
    std::map<uint16, const tls_supported_group_desc_t*> _supported_group_descs;

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    std::map<uint16, const tls_cert_compression_algid_desc_t*> _cert_compression_algid_descs;
    std::map<uint16, const tls_extension_type_desc_t*> _extension_type_descs;
    std::map<uint8, const tls_cert_status_type_desc_t*> _cert_status_type_descs;

    // https://www.iana.org/assignments/quic/quic.xhtml
    std::map<uint64, const tls_quic_trans_param_desc_t*> _quic_trans_param_descs;

    // https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
    std::map<uint16, const tls_aead_alg_desc_t*> _aead_alg_descs;

    // todo ...
    std::map<uint16, const tls_cipher_suite_t*> _cipher_suites;

    std::map<uint16, std::string> _tls_version;
    std::map<uint8, std::string> _cert_status_types;

    bool _load;
};

}  // namespace net
}  // namespace hotplace

#endif

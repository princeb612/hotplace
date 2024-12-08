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

#ifndef __HOTPLACE_SDK_NET_TLSADVISOR__
#define __HOTPLACE_SDK_NET_TLSADVISOR__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tlsspec/types.hpp>

namespace hotplace {
namespace net {

struct tls_alg_info_t {
    uint16 alg;
    crypt_algorithm_t cipher;
    crypt_mode_t mode;
    uint8 tagsize;
    hash_algorithm_t mac;
    hash_algorithm_t mac_tls1;
};
hash_algorithm_t algof_mac(const tls_alg_info_t* info);
hash_algorithm_t algof_mac1(const tls_alg_info_t* info);

class tls_advisor {
   public:
    static tls_advisor* get_instance();
    ~tls_advisor();

    std::string content_type_string(uint8 type);
    std::string handshake_type_string(uint8 type);
    std::string tls_version_string(uint16 code);
    std::string tls_extension_string(uint16 code);
    std::string cipher_suite_string(uint16 code);
    const tls_alg_info_t* hintof_tls_algorithm(uint16 code);
    const hint_blockcipher_t* hintof_blockcipher(uint16 code);
    const hint_digest_t* hintof_digest(uint16 code);
    hash_algorithm_t hash_alg_of(uint16 code);
    std::string compression_method_string(uint8 code);

    /**
     * RFC 5246 7.2.  Alert Protocol
     * RFC 8446 6.  Alert Protocol
     */
    std::string alert_level_string(uint8 code);
    std::string alert_desc_string(uint8 code);

    // tls_extension_server_name 0x0000
    std::string sni_nametype_string(uint16 code);
    // tls_extension_status_request 0x0005
    std::string cert_status_type_string(uint8 code);
    // tls_extension_supported_groups 0x000a
    std::string named_curve_string(uint16 code);
    // tls_extension_ec_point_formats 0x000b
    std::string ec_point_format_string(uint8 code);
    // tls_extension_signature_algorithms 0x000d
    std::string signature_scheme_string(uint16 code);
    // tls_extension_psk_key_exchange_modes 0x002d
    std::string psk_key_exchange_mode_string(uint8 mode);
    // tls_extension_quic_transport_parameters 0x0039
    std::string quic_param_string(uint16 code);

   protected:
    tls_advisor();
    void load_resource();
    void load_content_types();
    void load_handshake_types();
    void load_tls_version();
    void load_tls_extensions();
    void load_cipher_suites();
    void load_tls_alerts();
    void load_named_curves();
    void load_ec_point_formats();
    void load_signature_schemes();
    void load_psk_kem();
    void load_certificate_related();
    void load_quic_param();

    static tls_advisor _instance;
    critical_section _lock;
    std::map<uint8, std::string> _content_types;
    std::map<uint8, std::string> _handshake_types;
    std::map<uint16, std::string> _tls_version;
    std::map<uint16, std::string> _tls_extensions;
    std::map<uint16, std::string> _cipher_suites;
    std::map<uint16, const tls_alg_info_t*> _tls_alg_info;
    std::map<uint8, std::string> _tls_alert_level;
    std::map<uint16, std::string> _tls_alert_descriptions;
    std::map<uint8, std::string> _cert_status_types;

    // tls_extension_supported_groups 0x000a
    std::map<uint16, std::string> _named_curves;
    // tls_extension_ec_point_formats 0x000b
    std::map<uint8, std::string> _ec_point_formats;
    // tls_extension_signature_algorithms 0x000d
    std::map<uint16, std::string> _signature_schemes;
    // tls_extension_psk_key_exchange_modes 0x0002d
    std::map<uint8, std::string> _psk_kem;
    // tls_extension_quic_transport_parameters 0x0039
    std::map<uint16, std::string> _quic_params;

    bool _load;
};

extern const tls_alg_info_t tls_alg_info[];
extern const size_t sizeof_tls_alg_info;

}  // namespace net
}  // namespace hotplace

#endif

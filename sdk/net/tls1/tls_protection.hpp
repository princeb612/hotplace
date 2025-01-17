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

#ifndef __HOTPLACE_SDK_NET_TLS1_PROTECTION__
#define __HOTPLACE_SDK_NET_TLS1_PROTECTION__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

class tls_protection {
   public:
    /**
     * @brief    TLS protection
     * @param    uint8 mode [inopt] see tls_mode_t
     */
    tls_protection(uint8 mode = -1);
    ~tls_protection();

    uint8 get_mode();
    tls_message_flow_t get_flow();
    void set_flow(tls_message_flow_t flow);

    /**
     * @brief   cipher suite
     * @remarks after server_hello
     */
    uint16 get_cipher_suite();
    void set_cipher_suite(uint16 ciphersuite);
    uint16 get_record_version();
    void set_record_version(uint16 version);
    bool is_kindof_tls();
    bool is_kindof_dtls();
    uint16 get_tls_version();
    void set_tls_version(uint16 version);
    /**
     * @brief   transcript hash
     * @sample
     *          auto hash = get_transcript_hash;
     *          if (hash) { // after server_hello
     *              hash->digest(stream, size, context_hash);
     *              hash->release();
     *          }
     */
    transcript_hash* get_transcript_hash();
    /**
     * hash(handshake)
     */
    return_t calc_transcript_hash(tls_session* session, const byte_t* stream, size_t size);
    return_t calc_transcript_hash(tls_session* session, const byte_t* stream, size_t size, binary_t& digest);
    return_t reset_transcript_hash(tls_session* session);
    return_t calc_context_hash(tls_session* session, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& digest);
    /**
     *      "CH"  : client_hello key_share
     *      "SH"  : server_hello key_share
     *      "CKE" : client key exchange
     *      "SKE" : server key exchange
     *      "CC"  : client certificate
     *      "SC"  : server certifcate
     */
    crypto_key& get_keyexchange();

    void use_pre_master_secret(bool use);
    bool use_pre_master_secret();
    /**
     * @brief   calc
     * @param   tls_session* session [in]
     * @param   tls_hs_type_t type [in]
     */
    return_t calc(tls_session* session, tls_hs_type_t type, tls_direction_t dir);
    return_t calc_psk(tls_session* session, const binary_t& binder_hash, const binary_t& psk_binder);

    void get_item(tls_secret_t type, binary_t& item);
    const binary_t& get_item(tls_secret_t type);
    void set_item(tls_secret_t type, const binary_t& item);
    void set_item(tls_secret_t type, const byte_t* stream, size_t size);
    void clear_item(tls_secret_t type);

    size_t get_header_size();
    uint8 get_tag_size();

    return_t build_iv(tls_session* session, tls_secret_t type, binary_t& iv, uint64 recordno);

    return_t get_tls13_key(tls_session* session, tls_direction_t dir, tls_secret_t& key, tls_secret_t& iv);
    return_t get_tls1_key(tls_session* session, tls_direction_t dir, tls_secret_t& key, tls_secret_t& mackey);

    return_t encrypt_tls13(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag,
                           stream_t* debugstream = nullptr);
    return_t encrypt_tls1(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, binary_t& maced,
                          stream_t* debugstream = nullptr);

    /**
     * @brief   TLS 1.3 decrypt
     * @remarks
     *          application_data
     *          |   dir                     | client  | server  | key/iv        |
     *          | 0 client session (C <- S) | decrypt | encrypt | server key/iv |
     *          | 1 server session (C -> S) | encrypt | decrypt | client key/iv |
     *
     *          encrypt(&server_session, record, protected_record);
     *          decrypt(&client_session, protected_record, record);
     */
    return_t decrypt_tls13(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, binary_t& tag,
                           stream_t* debugstream = nullptr);

    return_t decrypt_tls13(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, const binary_t& aad,
                           binary_t& tag, stream_t* debugstream = nullptr);
    /**
     * @brief   TLS 1 decrypt
     */
    return_t decrypt_tls1(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, stream_t* debugstream);
    /**
     * @brief   verify
     * @sample
     *          auto sign = get_crypto_sign(scheme);
     *          if (sign) {
     *              ret = sign->verify(pkey, stream, sign, signature);
     *              sign->release();
     *          }
     */
    crypto_sign* get_crypto_sign(uint16 scheme);

   private:
    uint8 _mode;  // see tls_mode_t
    tls_message_flow_t _flow;
    uint16 _ciphersuite;
    uint16 _record_version;
    uint16 _version;
    transcript_hash* _transcript_hash;
    critical_section _lock;
    crypto_key _keyexchange;  // psk_ke, psk_dhe_ke
    std::map<tls_secret_t, binary_t> _kv;
    bool _use_pre_master_secret;
};

}  // namespace net
}  // namespace hotplace

#endif

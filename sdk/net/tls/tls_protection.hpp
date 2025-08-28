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

#ifndef __HOTPLACE_SDK_NET_TLS_TLSPROTECTION__
#define __HOTPLACE_SDK_NET_TLS_TLSPROTECTION__

#include <sdk/base/basic/binaries.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>
#include <set>

namespace hotplace {
namespace net {

#define KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE "CH.priv"
#define KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE "SH.priv"
#define KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC "CH.pub"
#define KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC "SH.pub"
#define KID_TLS_CLIENT_KEY_EXCHANGE "CKE"
#define KID_TLS_SERVER_KEY_EXCHANGE "SKE"
#define KID_TLS_CLIENT_CERTIFICATE_PUBLIC "CC.pub"
#define KID_TLS_SERVER_CERTIFICATE_PUBLIC "SC.pub"
#define KID_TLS_CLIENT_CERTIFICATE_PRIVATE "CC.priv"
#define KID_TLS_SERVER_CERTIFICATE_PRIVATE "SC.priv"

class protection_context {
   public:
    protection_context();
    protection_context(const protection_context& rhs);
    protection_context(protection_context&& rhs);

    return_t negotiate(tls_session* session, uint16& cs, uint16& tlsver);

    void add_cipher_suite(uint16 cs);
    void add_signature_algorithm(uint16 sa);
    void add_supported_group(uint16 sg);
    void add_supported_version(uint16 sv);
    void add_ec_point_format(uint8 epf);

    void clear_cipher_suites();
    void clear_signature_algorithms();
    void clear_supported_groups();
    void clear_supported_versions();
    void clear_ec_point_formats();

    void for_each_cipher_suites(std::function<void(uint16, bool*)> fn) const;
    void for_each_signature_algorithms(std::function<void(uint16, bool*)> fn) const;
    void for_each_supported_groups(std::function<void(uint16, bool*)> fn) const;
    void for_each_supported_versions(std::function<void(uint16, bool*)> fn) const;
    void for_each_ec_point_formats(std::function<void(uint8, bool*)> fn) const;

    return_t select_from(const protection_context& rhs, tls_session* session);

    void set_cipher_suite(uint16 cs);
    uint16 get_cipher_suite(uint16 cs);

    uint16 get0_cipher_suite();
    uint16 get0_supported_version();
    uint16 select_signature_algorithm(crypto_kty_t kty);

    void clear();

   protected:
   private:
    std::list<uint16> _cipher_suites;         // tls_handshake_client_hello
    std::list<uint16> _signature_algorithms;  // tls_extension_signature_algorithms
    std::list<uint16> _supported_groups;      // tls_extension_supported_groups
    std::list<uint16> _supported_versions;    // tls_extension_client_supported_versions
    std::list<uint8> _ec_point_formats;       // tls_extension_ec_point_formats
    uint16 _cipher_suite;
};

class tls_protection {
    friend class tls_session;

   public:
    /**
     * @brief    TLS protection
     */
    tls_protection();
    ~tls_protection();

    ///////////////////////////////////////////////////////////////////////////
    // basic
    ///////////////////////////////////////////////////////////////////////////

    tls_flow_t get_flow();
    void set_flow(tls_flow_t flow);

    /**
     * @brief   cipher suite
     * @remarks after server_hello
     */
    uint16 get_cipher_suite();
    void set_cipher_suite(uint16 ciphersuite);
    uint16 get_lagacy_version();
    bool is_kindof_tls();
    bool is_kindof_dtls();
    bool is_kindof_tls12();
    bool is_kindof_tls13();
    uint16 get_tls_version();
    void set_tls_version(uint16 version);
    protection_context& get_protection_context();

    crypto_key& get_keyexchange();

    void use_pre_master_secret(bool use);
    bool use_pre_master_secret();

    t_binaries<tls_secret_t>& get_secrets();

    size_t get_header_size();
    static return_t negotiate(tls_session* session, uint16& ciphersuite, uint16& tlsversion);

    ///////////////////////////////////////////////////////////////////////////
    // hash
    ///////////////////////////////////////////////////////////////////////////
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
     * transcript hash
     *  update - full message
     *  update_transcript_hash - except DTLS-specific data
     *  calc_transcript_hash - except DTLS-specific data
     */
    return_t update_transcript_hash(tls_session* session, const byte_t* stream, size_t size);
    return_t calc_transcript_hash(tls_session* session, const byte_t* stream, size_t size, binary_t& digest);
    return_t reset_transcript_hash(tls_session* session);
    /**
     * calc partial context hash
     */
    return_t calc_context_hash(tls_session* session, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& digest);

    /**
     * RFC 5246 6.2.3.3.  AEAD Ciphers
     *   additional_data = seq_num + TLSCompressed.type +
     *                     TLSCompressed.version + TLSCompressed.length;
     *   AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext,
     *                                additional_data)
     *   TLSCompressed.fragment = AEAD-Decrypt(write_key, nonce,
     *                                         AEADEncrypted,
     *                                         additional_data)
     *
     * uint64(seq_num) || uint8(type) || uint16(version) || uint16(cipertext_wo_tag.size)
     *
     * RFC 6347 4.1.2.1.  MAC
     *   The DTLS MAC is the same as that of TLS 1.2. However, rather than
     *   using TLS's implicit sequence number, the sequence number used to
     *   compute the MAC is the 64-bit value formed by concatenating the epoch
     *   and the sequence number in the order they appear on the wire.  Note
     *   that the DTLS epoch + sequence number is the same length as the TLS
     *   sequence number.
     *
     * uint16(epoch) || uint48(seq_num) || uint8(type) || uint16(version) || uint16(cipertext_wo_tag.size)
     */
    // decrypt_aead TLS 1.2 AAD
    return_t build_tls12_aad_from_record(tls_session* session, binary_t& aad, const binary_t& record_header, uint64 record_no, uint8 size_nonce_explicit);
    // tls_record::do_write_header
    return_t write_aad(tls_session* session, tls_direction_t dir, binary_t& aad, uint8 content_type, uint32 version, uint64 recno, uint16 epoch, uint64 dtlsseq,
                       uint16 bodysize);

    ///////////////////////////////////////////////////////////////////////////
    // encryption
    // RFC 5246
    //     struct {
    //         ContentType type;
    //         ProtocolVersion version;
    //         uint16 length;
    //         select (SecurityParameters.cipher_type) {
    //             case stream: GenericStreamCipher;
    //             case block:  GenericBlockCipher;
    //             case aead:   GenericAEADCipher;
    //         } fragment;
    //     } TLSCiphertext;
    //     struct {
    //        opaque nonce_explicit[SecurityParameters.record_iv_length];
    //        aead-ciphered struct {
    //            opaque content[TLSCompressed.length];
    //        };
    //     } GenericAEADCipher;
    // RFC 5288
    //     struct {
    //        opaque salt[4];
    //        opaque nonce_explicit[8];
    //     } GCMNonce;
    ///////////////////////////////////////////////////////////////////////////
    return_t build_iv(tls_session* session, binary_t& nonce, const binary_t& iv, uint64 recordno);
    uint8 get_tag_size();

    return_t get_aead_key(tls_session* session, tls_direction_t dir, protection_space_t space, tls_secret_t& key, tls_secret_t& iv);
    return_t get_cbc_hmac_key(tls_session* session, tls_direction_t dir, tls_secret_t& key, tls_secret_t& mackey);
    /**
     * @brief encrypt
     * @param tls_session* session [in]
     * @param tls_direction_t dir [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @param const binary_t& additional [in] content header + IV in CBC, AAD in CCM/CCM_8/GCM
     * @param binary_t& tag [out]
     * @remarks
     *          RFC 5246 6.2.3.2.  CBC Block Cipher
     *          RFC 5246 6.2.3.3.  AEAD Ciphers
     */
    return_t encrypt(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, const binary_t& additional, binary_t& tag,
                     protection_space_t space = protection_default);

    // stream include a tag
    return_t decrypt(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext,
                     protection_space_t space = protection_default);
    return_t decrypt(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, binary_t& aad,
                     protection_space_t space = protection_default);
    // stream do not include a tag
    return_t decrypt(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, const binary_t& aad,
                     const binary_t& tag, protection_space_t space = protection_default);

    ///////////////////////////////////////////////////////////////////////////
    // calc
    ///////////////////////////////////////////////////////////////////////////
    /**
     * @brief   calc
     * @param   tls_session* session [in]
     * @param   tls_hs_type_t type [in]
     */
    return_t calc(tls_session* session, tls_hs_type_t type, tls_direction_t dir);
    return_t calc_keyblock(hash_algorithm_t hmac_alg, const binary_t& master_secret, const binary_t& client_hello_random, const binary_t& server_hello_random,
                           uint16 cs);
    return_t calc_psk(tls_session* session, const binary_t& binder_hash, const binary_t& psk_binder);
    return_t calc_finished(tls_direction_t dir, hash_algorithm_t alg, uint16 dlen, tls_secret_t& secret, binary_t& maced);

    ///////////////////////////////////////////////////////////////////////////
    // mask for DTLS 1.3/QUIC header protection (aes-128-ecb)
    ///////////////////////////////////////////////////////////////////////////
    return_t get_protection_mask_key(tls_session* session, tls_direction_t dir, protection_space_t space, tls_secret_t& secret);
    return_t protection_mask(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, binary_t& mask, size_t masklen,
                             protection_space_t space = protection_default);

   protected:
    return_t encrypt_aead(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag,
                          protection_space_t space = protection_default);
    return_t encrypt_cbc_hmac(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, const binary_t& iv, binary_t& maced);
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
     *
     *          stream include a tag
     */
    return_t decrypt_aead(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext,
                          protection_space_t space = protection_default);
    /**
     * @brief   decrypt
     * @remarks stream do not include a tag
     */
    return_t decrypt_aead(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, const binary_t& aad,
                          const binary_t& tag, protection_space_t space = protection_default);
    /**
     * @brief   TLS 1 decrypt
     */
    return_t decrypt_cbc_hmac(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext);

    void set_session(tls_session* session);

   private:
    tls_session* _session;              //
    tls_flow_t _flow;                   // TLS flow
    uint16 _ciphersuite;                // cipher suite negotiated
    uint16 _version;                    // negotiated version
    transcript_hash* _transcript_hash;  // transcript hash
    critical_section _lock;             // lock
    crypto_key _keyexchange;            // key
    t_binaries<tls_secret_t> _secrets;  // secrets
    bool _use_pre_master_secret;        // test

    uint8 _key_exchange_mode;               // psk_ke, psk_dhe_ke
    protection_context _handshake_context;  // context
};

}  // namespace net
}  // namespace hotplace

#endif

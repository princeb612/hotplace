/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * studying
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 *
 * RFC 8446 2.  Protocol Overview
 *
 *        Client                                           Server
 *
 * Key  ^ ClientHello
 * Exch | + key_share*
 *      | + signature_algorithms*
 *      | + psk_key_exchange_modes*
 *      v + pre_shared_key*       -------->
 *                                                   ServerHello  ^ Key
 *                                                  + key_share*  | Exch
 *                                             + pre_shared_key*  v
 *                                         {EncryptedExtensions}  ^  Server
 *                                         {CertificateRequest*}  v  Params
 *                                                {Certificate*}  ^
 *                                          {CertificateVerify*}  | Auth
 *                                                    {Finished}  v
 *                                <--------  [Application Data*]
 *      ^ {Certificate*}
 * Auth | {CertificateVerify*}
 *      v {Finished}              -------->
 *        [Application Data]      <------->  [Application Data]
 *
 *               +  Indicates noteworthy extensions sent in the
 *                  previously noted message.
 *
 *               *  Indicates optional or situation-dependent
 *                  messages/extensions that are not always sent.
 *
 *               {} Indicates messages protected using keys
 *                  derived from a [sender]_handshake_traffic_secret.
 *
 *               [] Indicates messages protected using keys
 *                  derived from [sender]_application_traffic_secret_N.
 *
 *                Figure 1: Message Flow for Full TLS Handshake
 */

#ifndef __HOTPLACE_SDK_NET_TLS1X__
#define __HOTPLACE_SDK_NET_TLS1X__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

// studying ...
enum tls_message_flow_t {
    tls_1_rtt = 0,
    tls_0_rtt = 1,
    tls_hello_retry_request = 2,
};

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
     * @param   tls_handshake_type_t type [in]
     */
    return_t calc(tls_session* session, tls_handshake_type_t type, tls_role_t role);
    return_t calc_psk(tls_session* session, const binary_t& binder_hash, const binary_t& psk_binder);

    void get_item(tls_secret_t type, binary_t& item);
    const binary_t& get_item(tls_secret_t type);
    void set_item(tls_secret_t type, const binary_t& item);
    void set_item(tls_secret_t type, const byte_t* stream, size_t size);
    void clear_item(tls_secret_t type);

    return_t build_iv(tls_session* session, tls_secret_t type, binary_t& iv, uint64 recordno);

    /**
     * @brief   TLS 1.3 decrypt
     * @remarks
     *          application_data
     *          |   role                    | client  | server  | key/iv        |
     *          | 0 client session (C <- S) | decrypt | encrypt | server key/iv |
     *          | 1 server session (C -> S) | encrypt | decrypt | client key/iv |
     *
     *          encrypt(&server_session, record, protected_record);
     *          decrypt(&client_session, protected_record, record);
     */
    return_t decrypt_tls13(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, binary_t& tag,
                           stream_t* debugstream = nullptr);

    return_t decrypt_tls13(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, const binary_t& aad,
                           binary_t& tag, stream_t* debugstream = nullptr);
    /**
     * @brief   TLS 1 decrypt
     */
    return_t decrypt_tls1(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, stream_t* debugstream);
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

class tls_session {
    friend class tls_protection;

   public:
    tls_session() {}

    tls_protection& get_tls_protection() { return _tls_protection; }

    struct roleinfo {
        tls_handshake_type_t hstype;
        bool apply_cipher_spec;
        uint64 record_no;

        roleinfo() : hstype(tls_handshake_hello_request), apply_cipher_spec(false), record_no(0) {}

        void set_status(tls_handshake_type_t type) { hstype = type; }
        tls_handshake_type_t get_status() { return hstype; }
        void change_cipher_spec() { apply_cipher_spec = true; }
        bool doprotect() { return apply_cipher_spec; }
        uint64 get_recordno(bool inc = false) { return inc ? record_no++ : record_no; }
        void inc_recordno() { ++record_no; }
        void reset_recordno() { record_no = 0; }
    };
    roleinfo& get_roleinfo(tls_role_t role) { return _roles[role]; }
    uint64 get_recordno(tls_role_t role, bool inc = false) { return get_roleinfo(role).get_recordno(inc); }
    void reset_recordno(tls_role_t role) {
        auto ver = get_tls_protection().get_tls_version();
        if ((tls_13 == ver) || (dtls_13 == ver)) {
            get_roleinfo(role).reset_recordno();
        }
    }

   protected:
    std::map<tls_role_t, roleinfo> _roles;
    tls_protection _tls_protection;
};

/**
 * @brief   dump
 * @param   stream_t* s [out]
 * @param   const byte_t* stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 * @remarks
 */
return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role = role_server);
return_t tls_dump_change_cipher_spec(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_alert(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_handshake(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role = role_server);
return_t tls_dump_application_data(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_extension(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_ack(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role = role_server);

bool is_basedon_tls13(uint16 ver);
bool is_kindof_tls(uint16 ver);
bool is_kindof_dtls(uint16 ver);

}  // namespace net
}  // namespace hotplace

#endif

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

#ifndef __HOTPLACE_SDK_NET_TLS_TLSSESSION__
#define __HOTPLACE_SDK_NET_TLS_TLSSESSION__

#include <queue>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/net/basic/trial/secure_prosumer.hpp>
#include <sdk/net/tls/tls_protection.hpp>

namespace hotplace {
namespace net {

enum session_type_t {
    session_type_tls = 1,    // TLS session
    session_type_dtls = 2,   // DTLS session
    session_type_quic = 3,   // QUIC
    session_type_quic2 = 4,  // QUIC Version 2
};

enum session_alert_flag_t : uint8 {
    session_alert_peek = (1 << 0),
};

/**
 *   tls_session session;
 *   session.get_keyvalue().set(key, value);
 */
enum sessioninfo_conf_t : uint8 {
    // uint64, session->get_session_info(dir).get_keyvalue()
    session_dtls_epoch = 1,        // record epoch
    session_dtls_seq = 2,          // record sequence
    session_dtls_message_seq = 3,  // handshake sequence
    session_ticket_lifetime = 4,   // RFC 8446 4.6.1. uint32
    session_ticket_age_add = 5,    // RFC 8446 4.6.1. uint32
    session_ticket_timestamp = 6,  // RFC 8446 4.2.11. see obfuscated_ticket_age
    session_key_share_group = 7,   // HRR, uint16
};
enum session_conf_t : uint16 {
    // uint16, session->get_keyvalue()
    // config
    session_conf_enable_encrypt_then_mac = 0x1001,        // TLS 1.2 EtM
    session_conf_enforce_key_share_group = 0x1002,        // TLS 1.3 key share group
    session_conf_enable_renegotiation = 0x1003,           // TLS 1.2 renegotiation
    session_conf_enable_extended_master_secret = 0x1004,  // extended master secret
    // status
    session_tls_version = 0x2001,             // TLS version
    session_encrypt_then_mac = 0x2002,        // TLS 1.2 EtM
    session_handshake_finished = 0x2003,      // if finished HRR->0-RTT else HRR->1-RTT
    session_extended_master_secret = 0x2004,  // PRF("extended master secret", transcript_hash)
    // debug
    session_debug_deprecated_ciphersuite = 0x3001,  // to test unsupported cipher suite
};

class tls_session {
    friend class tls_protection;

   public:
    /**
     * @brief TLS/DTLS session
     */
    tls_session();
    ~tls_session();
    /**
     * @brief session
     * @param session_type_t type [in]
     */
    tls_session(session_type_t type);

    tls_protection& get_tls_protection();
    dtls_record_publisher& get_dtls_record_publisher();
    dtls_record_arrange& get_dtls_record_arrange();
    quic_session& get_quic_session();

    void set_type(session_type_t type);
    session_type_t get_type();

    void update_session_status(session_status_t status);
    void clear_session_status(uint32 status);
    void reset_session_status();
    uint32 get_session_status();
    return_t wait_change_session_status(uint32 status, unsigned msec, bool waitall = true);
    void set_hook_change_session_status(std::function<void(tls_session*, uint32)> func);
    void set_hook_param(void* param);
    void* get_hook_param();

    t_key_value<uint16, uint16>& get_keyvalue();

    struct alert {
        uint8 level;
        uint8 desc;
        alert(uint8 l, uint8 d) : level(l), desc(d) {}
    };

    class session_info {
       public:
        session_info();

        void set_status(tls_hs_type_t type);
        tls_hs_type_t get_status();

        uint64 get_recordno(bool inc = false, protection_level_t level = protection_default);
        void inc_recordno(protection_level_t level = protection_default);
        void reset_recordno(protection_level_t level = protection_default);
        void set_recordno(uint64 recordno, protection_level_t level = protection_default);  // for test vector

        void begin_protection();
        bool apply_protection();
        void reset_protection();

        void push_alert(uint8 level, uint8 desc);
        void get_alert(std::function<void(uint8, uint8)> func, uint8 flags = 0);
        bool has_alert(uint8 level = tls_alertlevel_fatal);

        t_key_value<uint8, uint64>& get_keyvalue();

       private:
        tls_hs_type_t _hstype;
        bool _protection;
        // RFC 9000 12.3.  Packet Numbers
        std::map<protection_level_t, uint64> _recordno_spaces;

        critical_section _info_lock;
        std::list<alert> _alerts;
        t_key_value<uint8, uint64> _kv;  // sessioninfo_conf_t
    };

    session_info& get_session_info(tls_direction_t dir);
    uint64 get_recordno(tls_direction_t dir, bool inc = false, protection_level_t level = protection_default);
    void reset_recordno(tls_direction_t dir, protection_level_t level = protection_default);

    /*
     * set test vector
     */
    void set_recordno(tls_direction_t dir, uint64 recno, protection_level_t level = protection_default);

    void addref();
    void release();

    void schedule(tls_handshake* handshake);
    void run_scheduled(tls_direction_t dir);

    // tls_extensions
    void schedule_extension(tls_extension* extension);
    void select_into_scheduled_extension(tls_extensions* extensions);
    void select_into_scheduled_extension(tls_extensions* extensions, tls_ext_type_t type);

    /**
     * If no common cryptographic parameters can be negotiated,
     * the server MUST abort the handshake with an appropriate alert.
     *
     * produce
     *      ret = protection.decrypt(session, dir, stream, declen, recpos, plaintext);
     *      if (errorcode_t::success != ret) {
     *         session->push_alert(warn, decrypt_error);
     *         // ...
     *      }
     * consume
     *      binanry_t bin;
     *      auto lambda = [&](uint8 level, uint8 desc) -> void {
     *          tls_record_application_data record(session);
     *          record.get_records().add(new tls_record_alert(session, level, desc));
     *          record.write(dir, bin);
     *      };
     *      session->get_alert(dir, lambda);
     *       // tcpsession->send(&bin[0], bin.size());
     */
    void push_alert(tls_direction_t dir, uint8 level, uint8 desc);
    void get_alert(tls_direction_t dir, std::function<void(uint8, uint8)> func, uint8 flags = 0);
    bool has_alert(tls_direction_t dir, uint8 level = tls_alertlevel_fatal);

    secure_prosumer* get_secure_prosumer();

   private:
    critical_section _lock;
    t_shared_reference<tls_session> _shared;

    std::map<tls_direction_t, session_info> _direction;
    std::queue<tls_handshake*> _handshake_que;
    std::list<tls_extension*> _extension_list;
    tls_protection _tls_protection;
    session_type_t _type;
    uint32 _status;
    semaphore _sem;  // _status related

    t_key_value<uint16, uint16> _kv;  // session_conf_t

    std::function<void(tls_session*, uint32)> _change_status_hook;
    void* _hook_param;

    /**
     * session_type_dtls
     * unnecessary if session_type is TLS
     */
    critical_section _dtls_lock;
    dtls_record_publisher* _dtls_record_publisher;
    dtls_record_arrange* _dtls_record_arrange;
    quic_session* _quic_session;
    secure_prosumer _prosumer;
};

}  // namespace net
}  // namespace hotplace

#endif

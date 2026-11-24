/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_session.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSSESSION__
#define __HOTPLACE_SDK_NET_TLS_TLSSESSION__

#include <hotplace/sdk/base/nostd/keyvalue.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/net/basic/trial/secure_prosumer.hpp>
#include <hotplace/sdk/net/basic/types.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/types.hpp>
#include <memory>
#include <queue>
#include <vector>

namespace hotplace {
namespace net {

struct tls_resumption_ticket {
    binary_t identity;
    binary_t server_name;  // SNI associated with this cached PSK
    binary_t alpn;         // negotiated ALPN associated with this cached PSK
    binary_t nonce;
    binary_t psk;
    uint32 lifetime;
    uint32 age_add;
    uint64 timestamp;
    uint16 version;
    uint16 cipher_suite;
    uint32 max_early_data_size;

    tls_resumption_ticket() : lifetime(0), age_add(0), timestamp(0), version(0), cipher_suite(0), max_early_data_size(0) {}
};

/**
 * TLS 1.2 RFC 5077 state referenced by an opaque SessionTicket identity.
 * Active and pending entries are isolated from the TLS 1.3 PSK cache.
 */
struct tls12_resumption_ticket {
    binary_t identity;
    binary_t master_secret;
    binary_t server_name;
    binary_t alpn;
    uint32 lifetime;
    uint64 timestamp;
    uint16 version;
    uint16 cipher_suite;
    bool extended_master_secret;
    bool encrypt_then_mac;

    tls12_resumption_ticket() : lifetime(0), timestamp(0), version(0), cipher_suite(0), extended_master_secret(false), encrypt_then_mac(false) {}
};

class HOTPLACE_NET_API tls12_resumption_ticket_store {
   public:
    void store(const tls12_resumption_ticket& ticket);
    std::vector<tls12_resumption_ticket> get();
    bool find(const binary_t& identity, tls12_resumption_ticket& ticket);
    void remove(const binary_t& identity);

   private:
    critical_section _lock;
    std::vector<tls12_resumption_ticket> _tickets;
};

enum session_type_t {
    tls = 1,    // TLS session
    dtls = 2,   // DTLS session
    quic = 3,   // QUIC
    quic2 = 4,  // QUIC Version 2
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
    session_dtls_epoch = 1,                     // record epoch
    session_dtls_seq = 2,                       // record sequence
    session_dtls_message_seq = 3,               // handshake sequence
    session_ticket_lifetime = 4,                // RFC 8446 4.6.1. uint32
    session_ticket_age_add = 5,                 // RFC 8446 4.6.1. uint32
    session_ticket_timestamp = 6,               // RFC 8446 4.2.11. see obfuscated_ticket_age
    session_key_share_group = 7,                // key share group (tls_extension_key_share)
    session_hrr = 8,                            // HRR (tls_extension_key_share case pubkeylen == 0)
    session_record_size_limit = 9,              // RFC 8449: receive limit advertised by this endpoint
    session_tls13_key_usage_bytes = 10,         // RFC 9846 5.5: plaintext encrypted with the current directional traffic key
    session_early_data_limit = 11,              // RFC 8446 4.2.10: selected ticket's max_early_data_size
    session_early_data_received = 12,           // RFC 8446 4.2.10: client early-data bytes received on this connection
    session_early_data_offered = 13,            // RFC 8446 4.2.10: early_data was present in ClientHello
    session_early_data_finished = 14,           // Client early-data phase ended (EndOfEarlyData or client Finished)
    session_early_data_accepted = 15,           // RFC 8446: server accepted early data in EncryptedExtensions
    session_early_data_sent = 16,               // RFC 8446: client early-data bytes sent on this connection
    session_early_data_discard_limit = 17,      // RFC 8446: server rejection-skip byte limit
    session_early_data_discarded = 18,          // RFC 8446: rejected early-data ciphertext bytes skipped
    session_early_data_offered_initial = 19,    // RFC 9846: ClientHello1 offered early_data; retain through HRR
    session_ticket_max_early_data_size = 20,    // RFC 8446: max_early_data_size from the legacy latest-ticket view
    session_early_data_discarded_records = 21,  // Local limit: rejected early-data TLS records skipped
    session_ticket_pending = 22,                // RFC 5077: a received ticket awaits authenticated server Finished
    session_ticket_pending_lifetime = 23,       // RFC 5077: pending ticket lifetime_hint
    session_ticket_pending_timestamp = 24,      // Local receipt time for the pending TLS 1.2 ticket
    session_tls12_renegotiation_ccs = 25,       // RFC 5746: this direction activated renegotiation keys at CCS
};
enum session_conf_t : uint16 {
    // uint16, session->get_keyvalue()
    // config
    session_conf_enable_encrypt_then_mac = 0x1001,        // TLS 1.2 EtM
    session_conf_enforce_key_share_group = 0x1002,        // TLS 1.3 key share group
    session_conf_enable_tls12_renegotiation = 0x1003,     // TLS 1.2 renegotiation
    session_conf_enable_extended_master_secret = 0x1004,  // extended master secret
    // status
    session_tls_version = 0x2001,                           // TLS version
    session_encrypt_then_mac = 0x2002,                      // TLS 1.2 EtM
    session_handshake_finished = 0x2003,                    // if finished HRR->0-RTT else HRR->1-RTT
    session_extended_master_secret = 0x2004,                // PRF("extended master secret", transcript_hash)
    session_client_post_handshake_auth = 0x2006,            // RFC 9846 4.7.2: ClientHello offer for post-handshake authentication
    session_client_psk_identity_count = 0x2007,             // RFC 8446 4.2.11: identities offered in the latest ClientHello
    session_client_psk_modes_present = 0x2008,              // RFC 8446 4.2.9: psk_key_exchange_modes extension was offered
    session_client_psk_modes = 0x2009,                      // RFC 8446 4.2.9: bit mask of offered PSK key exchange modes
    session_client_psk_hash = 0x200A,                       // RFC 8446 4.2.11: hash associated with the offered PSK binder
    session_server_psk_selected_identity = 0x200B,          // RFC 8446 4.2.11: identity selected by the server
    session_server_psk_ticket_cipher_suite = 0x200C,        // RFC 8446 4.6.1: cipher suite that established the selected ticket PSK
    session_server_psk_key_exchange_mode = 0x200D,          // RFC 8446 4.2.9: selected psk_ke (0) or psk_dhe_ke (1) mode
    session_client_session_ticket_offered = 0x200E,         // RFC 5077: SessionTicket extension was offered in ClientHello
    session_client_session_ticket_offer_observed = 0x200F,  // RFC 5077: ClientHello offer state was observed
    session_tls12_ticket_candidate = 0x2010,                // RFC 5077: locally validated ticket candidate
    session_tls12_ticket_resumed = 0x2011,                  // RFC 5077: abbreviated handshake selected
    session_tls12_ticket_cipher_suite = 0x2012,             // Cipher suite bound to the candidate ticket
    session_tls12_ticket_identity_present = 0x2013,         // ClientHello carried a non-empty ticket identity
    session_tls12_ticket_ems = 0x2014,                      // EMS state bound to the cached TLS 1.2 ticket
    session_tls12_ticket_etm = 0x2015,                      // EtM state bound to the cached TLS 1.2 ticket
    session_tls12_ticket_acknowledged = 0x2016,             // ServerHello acknowledged ticket issuance
    session_client_session_ticket_offer_enabled = 0x2017,   // Client is prepared to receive TLS 1.2 tickets
    session_tls12_secure_renegotiation_offered = 0x2018,    // RFC 5746: initial ClientHello signaled secure renegotiation
    session_tls12_secure_renegotiation = 0x2019,            // RFC 5746: secure renegotiation was established
    // debug
    session_debug_deprecated_ciphersuite = 0x3001,  // to test unsupported cipher suite
};

enum class tls_session_copy_t {
    resumption = 1,
};

class HOTPLACE_NET_API tls_session {
    friend class tls_protection;

   public:
    /**
     * @brief TLS/DTLS session
     */
    tls_session();
    // Create a fresh connection session carrying only the state required for the selected copy purpose.
    // The caller owns the returned session and must release it.
    tls_session* duplicate(tls_session_copy_t type) const;
    tls_session(const tls_session& other) = delete;
    tls_session(tls_session&& other) = delete;
    ~tls_session();
    /**
     * @brief session
     * @param session_type_t type [in]
     */
    tls_session(session_type_t type);

    tls_session& operator=(const tls_session& other) = delete;
    tls_session& operator=(tls_session&& other) = delete;

    tls_protection& get_tls_protection();
    dtls_record_publisher& get_dtls_record_publisher();
    dtls_record_arrange& get_dtls_record_arrange();
    quic_session& get_quic_session();
    quic_packet_publisher& get_quic_packet_publisher();

    void set_type(session_type_t type);
    session_type_t get_type() const;
    return_t generate_ticket_nonce(binary_t& nonce);
    void store_resumption_ticket(const tls_resumption_ticket& ticket);
    std::vector<tls_resumption_ticket> get_resumption_tickets() const;
    bool find_resumption_ticket(const binary_t& identity, tls_resumption_ticket& ticket);
    void remove_resumption_ticket(const binary_t& identity);
    void set_tls12_resumption_ticket_store(const std::shared_ptr<tls12_resumption_ticket_store>& store);
    void stage_tls12_resumption_ticket(const tls12_resumption_ticket& ticket);
    bool confirm_tls12_resumption_ticket(const binary_t& identity);
    void discard_tls12_pending_resumption_ticket(const binary_t& identity);
    void discard_all_pending_tls12_resumption_tickets();
    std::vector<tls12_resumption_ticket> get_tls12_resumption_tickets();
    std::vector<tls12_resumption_ticket> get_pending_tls12_resumption_tickets();
    bool find_tls12_resumption_ticket(const binary_t& identity, tls12_resumption_ticket& ticket);
    void remove_tls12_resumption_ticket(const binary_t& identity);
    void set_offered_resumption_tickets(const std::vector<tls_resumption_ticket>& tickets);
    std::vector<tls_resumption_ticket> get_offered_resumption_tickets();
    void set_early_data_ticket(const tls_resumption_ticket& ticket);
    tls_resumption_ticket get_early_data_ticket();
    void clear_early_data_ticket();
    /**
     * Configure the maximum ciphertext bytes to skip while rejecting 0-RTT.
     * The default is 1 MiB; set this on the server before parsing ClientHello.
     * Zero disables rejected-record skipping. The independent 64-record and
     * TLSCiphertext per-record limits still apply.
     */
    void set_early_data_discard_limit(uint64 limit);
    uint64 get_early_data_discard_limit() const;
    void set_client_server_name(const binary_t& server_name);
    binary_t get_client_server_name();

    void update_session_status(session_status_t status);
    void clear_session_status(uint32 status);
    void reset_session_status();
    uint32 get_session_status() const;
    return_t wait_change_session_status(uint32 status, unsigned msec, bool waitall = true);
    void set_hook_change_session_status(std::function<void(tls_session*, uint32)> func);
    void set_hook_param(void* param);
    void* get_hook_param();

    t_key_value<uint16, uint16>& get_keyvalue();

    struct alert {
        tls_alertlevel_t level;
        tls_alertdesc_t desc;
        alert(tls_alertlevel_t l, tls_alertdesc_t d) : level(l), desc(d) {}
    };

    class HOTPLACE_NET_API session_info {
       public:
        session_info();

        void set_status(tls_handshake_type_t type);
        tls_handshake_type_t get_status() const;

        uint64 get_recordno(protection_space_t space = protection_space_t::tls) const;
        void inc_recordno(protection_space_t space = protection_space_t::tls);
        void reset_recordno(protection_space_t space = protection_space_t::tls);
        void set_recordno(uint64 recordno, protection_space_t space = protection_space_t::tls);  // for test vector

        void begin_protection();
        bool apply_protection() const;
        void reset_protection();

        // TLS 1.2 keeps the active cipher suite per direction across renegotiation.
        void set_active_cipher_suite(uint16 ciphersuite);
        uint16 get_active_cipher_suite() const;

        void push_alert(tls_alertlevel_t level, tls_alertdesc_t desc);
        void get_alert(std::function<void(tls_alertlevel_t, tls_alertdesc_t)> func, uint8 flags = 0);
        bool has_alert(tls_alertlevel_t level = tls_alertlevel_t::fatal);

        t_key_value<uint8, uint64>& get_keyvalue();

       private:
        tls_handshake_type_t _hstype;
        bool _protection;
        uint16 _active_cipher_suite;  // zero until this direction switches at CCS
        // RFC 9000 12.3.  Packet Numbers
        std::map<protection_space_t, uint64> _recordno_spaces;

        critical_section _info_lock;
        std::list<alert> _alerts;
        t_key_value<uint8, uint64> _kv;  // sessioninfo_conf_t
    };

    bool register_certificate_request_context(const binary_t& context);
    void reset_certificate_request_contexts();

    session_info& get_session_info(tls_direction_t dir);
    uint64 get_recordno(tls_direction_t dir, protection_space_t space = protection_space_t::tls);
    void inc_recordno(tls_direction_t dir, protection_space_t space = protection_space_t::tls);
    void reset_recordno(tls_direction_t dir, protection_space_t space = protection_space_t::tls);

    /*
     * set test vector
     */
    void set_recordno(tls_direction_t dir, uint64 recno, protection_space_t space = protection_space_t::tls);

    void addref();
    void release();

    void schedule(tls_handshake* handshake);
    void run_scheduled(tls_direction_t dir);

    // tls_extensions
    void schedule_extension(tls_extension* extension);
    void select_into_scheduled_extension(tls_extensions* extensions);
    void select_into_scheduled_extension(tls_extensions* extensions, tls_extension_type_t type);
    void clear_scheduled_extensions();

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
     *      auto lambda = [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
     *          tls_record_application_data record(session);
     *          record.get_records().add(new tls_record_alert(session, level, desc));
     *          record.write(dir, bin);
     *      };
     *      session->get_alert(dir, lambda);
     *       // tcpsession->send(bin.data(), bin.size());
     */
    void push_alert(tls_direction_t dir, tls_alertlevel_t level, tls_alertdesc_t desc);
    void get_alert(tls_direction_t dir, std::function<void(tls_alertlevel_t, tls_alertdesc_t)> func, uint8 flags = 0);
    bool has_alert(tls_direction_t dir, tls_alertlevel_t level = tls_alertlevel_t::fatal);

    tls_composer* get_tls_composer();
    secure_prosumer* get_secure_prosumer();

   private:
    mutable critical_section _lock;  // const snapshot accessors synchronize without copying the lock
    t_shared_reference<tls_session> _shared;

    std::map<tls_direction_t, session_info> _direction;
    critical_section _certificate_request_context_lock;
    std::vector<binary_t> _certificate_request_contexts;
    std::queue<tls_handshake*> _handshake_que;
    std::list<tls_extension*> _extension_list;
    tls_protection _tls_protection;
    session_type_t _type;
    uint32 _status;
    std::vector<tls_resumption_ticket> _resumption_tickets;  // TLS 1.3 PSK tickets
    std::shared_ptr<tls12_resumption_ticket_store> _tls12_ticket_store;
    std::vector<tls12_resumption_ticket> _pending_tls12_resumption_tickets;
    std::vector<tls_resumption_ticket> _offered_resumption_tickets;
    tls_resumption_ticket _early_data_ticket;
    uint64 _early_data_discard_limit = 1024 * 1024;
    binary_t _client_server_name;
    semaphore _sem;  // _status related

    t_key_value<uint16, uint16> _kv;  // session_conf_t

    std::function<void(tls_session*, uint32)> _change_status_hook;
    void* _hook_param;

    /**
     * session_type_t::dtls
     * unnecessary if session_type is TLS
     */
    critical_section _dtls_lock;
    tls_composer* _composer;
    dtls_record_publisher* _dtls_record_publisher;
    dtls_record_arrange* _dtls_record_arrange;
    quic_session* _quic_session;
    critical_section _quic_lock;
    secure_prosumer _prosumer;
};

}  // namespace net
}  // namespace hotplace

#endif

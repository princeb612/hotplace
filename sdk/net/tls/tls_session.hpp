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
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/net/tls/tls_protection.hpp>

namespace hotplace {
namespace net {

enum session_type_t {
    session_tls = 1,    // TLS/DTLS session
    session_quic = 2,   // QUIC
    session_quic2 = 3,  // QUIC Version 2
};

enum session_status_t : uint16 {
    session_key_exchanged = (1 << 0),
    session_server_cert_verified = (1 << 1),  // tls_handshake_certificate_verify
    session_server_finished = (1 << 2),       // tls_handshake_finished
    session_client_finished = (1 << 3),       // tls_handshake_finished
    session_client_close_notified = (1 << 14),
    session_server_close_notified = (1 << 15),
};

/**
 *   tls_session session;
 *   session.get_conf().set(key, value);
 */
enum session_conf_t {
    session_debug_deprecated_ciphersuite = 1000,  // to test unsupported cipher suite
};

class tls_session {
    friend class tls_protection;

   public:
    /**
     * @brief TLS/DTLS session
     */
    tls_session();
    /**
     * @brief session
     * @param session_type_t type [in]
     */
    tls_session(session_type_t type);

    tls_protection& get_tls_protection();
    void set_type(session_type_t type);
    session_type_t get_type();

    void update_session_status(session_status_t status);
    uint16 get_session_status();
    return_t wait_change_session_status(uint16 status, unsigned msec);

    t_key_value<uint16, uint16>& get_conf();

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

       private:
        tls_hs_type_t _hstype;
        bool _protection;
        // RFC 9000 12.3.  Packet Numbers
        std::map<protection_level_t, uint64> _recordno_spaces;
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
     *      if (numberof_alerts()) {
     *          session->pop_alert(level, desc);
     *          tls_record_application_data record(session);
     *          record.get_records().add(new tls_record_alert(session, level, desc));
     *          record.write(dir, bin);
     *          // tcpsession->send(&bin[0], bin.size());
     *      }
     */
    void push_alert(uint8 level, uint8 desc);
    size_t numberof_alerts();
    return_t pop_alert(uint8& level, uint8& desc);

   private:
    critical_section _lock;
    t_shared_reference<tls_session> _shared;

    std::map<tls_direction_t, session_info> _direction;
    std::queue<tls_handshake*> _que;
    tls_protection _tls_protection;
    session_type_t _type;
    uint16 _status;
    semaphore _sem;  // _status related

    struct alert {
        uint8 level;
        uint8 desc;
        alert(uint8 l, uint8 d) : level(l), desc(d) {}
    };
    std::queue<alert> _alerts;

    t_key_value<uint16, uint16> _kv;
};

}  // namespace net
}  // namespace hotplace

#endif

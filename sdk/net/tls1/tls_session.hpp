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

#ifndef __HOTPLACE_SDK_NET_TLS1_SESSION__
#define __HOTPLACE_SDK_NET_TLS1_SESSION__

#include <queue>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/tls_protection.hpp>

namespace hotplace {
namespace net {

class tls_session {
    friend class tls_protection;

   public:
    tls_session();

    tls_protection& get_tls_protection();

    class session_info {
       public:
        session_info();

        void set_status(tls_hs_type_t type);
        tls_hs_type_t get_status();
        void change_cipher_spec();
        bool doprotect();
        uint64 get_recordno(bool inc = false);
        void inc_recordno();
        void reset_recordno();

       private:
        tls_hs_type_t hstype;
        bool apply_cipher_spec;
        uint64 record_no;
    };

    session_info& get_session_info(tls_direction_t dir);
    uint64 get_recordno(tls_direction_t dir, bool inc = false);
    void reset_recordno(tls_direction_t dir);

    void addref();
    void release();

    void schedule(tls_handshake* handshake);
    void run_scheduled(tls_direction_t dir);

   private:
    critical_section _lock;
    std::map<tls_direction_t, session_info> _direction;
    std::queue<tls_handshake*> _que;
    tls_protection _tls_protection;
    t_shared_reference<tls_session> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif

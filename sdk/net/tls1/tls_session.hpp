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

#ifndef __HOTPLACE_SDK_NET_TLS1_SESSION__
#define __HOTPLACE_SDK_NET_TLS1_SESSION__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/types.hpp>

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

   private:
    std::map<tls_direction_t, session_info> _direction;
    tls_protection _tls_protection;
    t_shared_reference<tls_session> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif

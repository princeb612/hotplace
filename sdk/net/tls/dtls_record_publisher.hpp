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

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSRECORDPUBLISHER__
#define __HOTPLACE_SDK_NET_TLS_DTLSRECORDPUBLISHER__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <hotplace/sdk/net/tls/types.hpp>
#include <queue>

namespace hotplace {
namespace net {

enum dtls_record_publisher_flag_t : uint32 {
    // tls_record_handshake contains multiple handshakes if possible
    // if not set tls_record_handshake .. single handshake
    dtls_record_publisher_multi_handshakes = (1 << 0),
};

/**
 * @brief   fragmentation
 * @example
 *          tls_session session_client(session_type_dtls);
 *          session_server.get_dtls_record_publisher().set_flags(dtls_record_publisher_multi_handshakes);
 *          session_client.get_dtls_record_publisher().set_fragment_size(1024);
 *
 *          // construct SH, CERT, SKE, SHD
 *          tls_record_handshake record(session);
 *          record
 *              .add(tls_hs_server_hello, session,
 *                   [&](tls_handshake* hs) -> return_t {
 *                       auto handshake = (tls_handshake_server_hello*)hs;
 *
 *                       handshake->set_cipher_suite(server_cs);
 *
 *                       handshake->get_extensions()
 *                           .add(tls_ext_encrypt_then_mac, dir, handshake)
 *                           .add(tls_ext_renegotiation_info, dir, handshake)
 *                           .add(tls_ext_ec_point_formats, dir, handshake,
 *                                [](tls_extension* extension) -> return_t {
 *                                    (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
 *                                    return success;
 *                                })
 *                           .add(tls_ext_supported_groups, dir, handshake,  //
 *                                [](tls_extension* extension) -> return_t {
 *                                    (*(tls_extension_supported_groups*)extension).add("x25519");
 *                                    return success;
 *                                });
 *
 *                       return success;
 *                   })
 *              .add(tls_hs_certificate, session)
 *              .add(tls_hs_server_key_exchange, session)
 *              .add(tls_hs_server_hello_done, session);
 *
 *          // fragmentation
 *          ret = record.get_session()->get_dtls_record_publisher().publish(record, dir, func);
 */
class dtls_record_publisher {
    friend class tls_session;

   public:
    dtls_record_publisher();
    /**
     * DTLS 1.2
     *  RTL_FIELD_SIZE(tls_content_t, dtls) + sizeof(dtls_handshake_t) + fragment
     */
    void set_fragment_size(uint16 size);
    uint16 get_fragment_size();

    /**
     * @comments
     *      not the exact boundary size
     *      cf. quic_packet_publisher::set_payload_size
     */
    void set_segment_size(uint16 size);
    uint16 get_max_size();

    /**
     * @brief publish
     * @param tls_record* record [in]
     * @param tls_direction_t dir [in]
     * @param std::function<void (tls_session*, binary_t&)> func [in]
     */
    return_t publish(tls_record* record, tls_direction_t dir, std::list<binary_t>& container);
    return_t publish(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);
    return_t publish(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);

    void set_flags(uint32 flags);
    uint32 get_flags();

   protected:
    void set_session(tls_session* session);
    tls_session* get_session();

   private:
    tls_session* _session;
    uint16 _fragment_size;
    uint16 _segment_size;
    uint32 _flags;
};

}  // namespace net
}  // namespace hotplace

#endif

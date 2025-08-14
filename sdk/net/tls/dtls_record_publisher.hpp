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

#include <queue>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

enum dtls_record_publisher_flag_t : uint32 {
    // tls_record_handshake contains multiple handshakes if possible
    // if not set tls_record_handshake .. single handshake
    dtls_record_publisher_multi_handshakes = (1 << 0),
};

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

    void set_max_size(uint16 size);
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
    uint16 _max_size;
    uint32 _flags;
};

}  // namespace net
}  // namespace hotplace

#endif

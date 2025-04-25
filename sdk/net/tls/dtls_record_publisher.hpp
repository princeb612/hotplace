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
     * @brief publish
     * @param std::vector<tls_record*>& records [out]
     * @param tls_record_handshake* record [in]
     * @param tls_direction_t dir [in]
     */
    return_t publish(std::vector<tls_record*>& records, tls_record* record, tls_direction_t dir);

   protected:
    void set_session(tls_session* session);
    tls_session* get_session();

   private:
    tls_session* _session;
    uint16 _fragment_size;
};

}  // namespace net
}  // namespace hotplace

#endif

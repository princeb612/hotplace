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

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSRECORDARRANGE__
#define __HOTPLACE_SDK_NET_TLS_DTLSRECORDARRANGE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/net/tls/types.hpp>
#include <queue>

namespace hotplace {
namespace net {

/**
 * @brief DTLS packet re-ordering
 * @desc
 *        RFC 6347 4.1.  Record Layer
 *          produce
 *            record epoch:0 seq:0
 *            record epoch:0 seq:2
 *            record epoch:0 seq:1
 *          consume
 *            record epoch:0 seq:0
 *            record epoch:0 seq:1
 *            record epoch:0 seq:2
 * @example
 *          tls_session session(session_type_dtls);
 *          auto& arrange = session.get_dtls_record_arrange();
 *          arrange.produce(dgram, dgramsize, addr, addrlen);
 *          arrange.consume(epoch, seq, packet, addr, &addrlen);  // reorder
 */
class dtls_record_arrange {
    friend class tls_session;

   public:
    dtls_record_arrange();
    ~dtls_record_arrange();

    /**
     * @brief produce
     * @param const sockaddr* addr [in]
     * @param socklen_t addrlen [in]
     * @param const byte_t* stream [in]
     * @param size_t size [in]
     */
    return_t produce(const sockaddr* addr, socklen_t addrlen, const byte_t* stream, size_t size);
    /**
     * @brief consume
     * @param const sockaddr* addr [out]
     * @param socklen_t addrlen [in]
     * @param binary_t& bin [out]
     */
    return_t consume(const sockaddr* addr, socklen_t addrlen, binary_t& bin);
    /**
     * @brief consume
     * @param const sockaddr* addr [in]
     * @param socklen_t addrlen [in]
     * @param uint16& epoch [out]
     * @param uint64& seq [out]
     * @param binary_t& bin [out]
     */
    return_t consume(const sockaddr* addr, socklen_t addrlen, uint16& epoch, uint64& seq, binary_t& bin);

    /**
     * @param uint16 epoch [in]
     * @param uint64 seq [in]
     * @return uint16 || uint48
     */
    static uint64 make_epoch_seq(uint16 epoch, uint64 seq);
    /**
     * @param uint64 key [in] uint16 || uint48
     * @param uint16& epoch [out]
     * @param uint64& seq [in]
     */
    static void get_epoch_seq(uint64 key, uint16& epoch, uint64& seq);

   protected:
    void set_session(tls_session* session);
    tls_session* get_session();

   private:
    tls_session* _session;

    critical_section _lock;
    struct per_cookie_t {
        sockaddr_storage_t addr;
        uint16 epoch;
        uint64 seq;
        std::map<uint64, binary_t> packets;  // re-order

        per_cookie_t() : epoch(0), seq(0) { memset(&addr, 0, sizeof(addr)); }
    };
    std::map<binary_t, per_cookie_t> _pool;  // group by cookie
};

}  // namespace net
}  // namespace hotplace

#endif

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

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSRECORDREORDER__
#define __HOTPLACE_SDK_NET_TLS_DTLSRECORDREORDER__

#include <queue>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/tls/types.hpp>

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
 */
class dtls_record_reorder {
   public:
    dtls_record_reorder();
    ~dtls_record_reorder();

    return_t produce(const byte_t* stream, size_t size);
    return_t consume(binary_t& bin);
    return_t consume(uint16& epoch, uint64& seq, binary_t& bin);

    static uint64 make_epoch_seq(uint16 epoch, uint64 seq);
    static void get_epoch_seq(uint64 key, uint16& epoch, uint64& seq);

   protected:
    tls_session* get_session();

    tls_session* _session;
    uint16 _epoch;
    uint64 _seq;

    critical_section _lock;
    std::map<uint64, binary_t> _packets;  // re-order
};

}  // namespace net
}  // namespace hotplace

#endif

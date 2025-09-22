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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSESSION__
#define __HOTPLACE_SDK_NET_TLS_QUICSESSION__

#include <hotplace/sdk/base/basic/binaries.hpp>
#include <hotplace/sdk/base/basic/keyvalue.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/net/http/qpack/qpack_dynamic_table.hpp>
#include <hotplace/sdk/net/http/qpack/qpack_encoder.hpp>
#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/quic_packet_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_streams.hpp>
#include <hotplace/sdk/net/tls/types.hpp>
#include <queue>

namespace hotplace {
namespace net {

class quic_session {
   public:
    quic_session();
    ~quic_session();

    /**
     * NCI
     */
    std::map<uint64, binary_t>& get_cid_tracker();
    /**
     * setting
     */
    t_key_value<uint64, uint64>& get_setting();
    /**
     * settings, headers
     */
    qpack_dynamic_table& get_dynamic_table();
    /**
     * ack
     */
    t_ovl_points<uint32>& get_pkns(protection_space_t space);
    /**
     * stream
     */
    quic_streams& get_streams();
    /**
     * publisher
     */
    quic_packet_publisher& get_quic_packet_publisher();

   protected:
   private:
    // NCI
    std::map<uint64, binary_t> _cid_tracker;
    // setting
    t_key_value<uint64, uint64> _setting;
    // settings, headers
    qpack_dynamic_table _qpack_dyntable;
    // ack
    std::map<protection_space_t, t_ovl_points<uint32>> _pkn;
    // stream
    quic_streams _streams;
    // publisjer
    quic_packet_publisher _quic_packet_publisher;
    // retransmission
    std::map<protection_space_t, t_binaries<uint32>> _retrans;
};

}  // namespace net
}  // namespace hotplace

#endif

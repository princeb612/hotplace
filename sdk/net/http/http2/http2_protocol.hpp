/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2PROTOCOL__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2PROTOCOL__

#include <sdk/net/server/network_protocol.hpp>  // network_protocol

namespace hotplace {
namespace net {

/**
 * @brief   protocol interpreter
 */
class http2_protocol : public network_protocol {
   public:
    http2_protocol();
    virtual ~http2_protocol();
    /**
     * @brief   check protocol
     * @param   void*           stream          [IN]
     * @param   size_t          stream_size     [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t is_kind_of(void* stream, size_t stream_size);
    /**
     * @brief   read stream
     * @param   IBufferStream*  stream          [IN]
     * @param   size_t*         request_size    [INOUT]
     * @param   PROTOCOL_STATE* state           [OUT]
     *                                              PROTOCOL_STATE_COMPLETE
     *                                              PROTOCOL_STATE_CRASH : drop
     * @param   int*            priority        [OUTOPT]
     * @return  error code (see error.hpp)
     * @remarks
     */
    virtual return_t read_stream(basic_stream* stream, size_t* request_size, protocol_state_t* state, int* priority = nullptr);
    /**
     * @brief   id
     */
    virtual const char* protocol_id();
};

}  // namespace net
}  // namespace hotplace

#endif
